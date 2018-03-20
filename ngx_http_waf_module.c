// Copyright (C) vislee

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * main_rule id:1001 "str:xxx"  "msg:test" "mz:ARGS|HEADERS|$HEADERS:cookie"
 * -> ARGS:1001
 * -> HEADERS:1001 (include cookie)
 * -> $HEADERS:cookie:1001
 *
 * basic_rule id:1002 "str:yyy" "msg:test" "mz:ARGS|$HEADERS:cookie"
 * -> ARGS:1002
 * -> $HEADERS:cookie:1002
 *
 * basic_rule "br:1001" "mz:$HEADERS_VAR:xxx"
 *
 * basic_rule "wl:1001,1002" 
            "mz:$ARGS_VAR:xxx|$ARGS_VAR_X:[a-z]{1,3}|$HEADERS_VAR_X:{a-z}{1,5}"
 * -> 1001: $ARGS ...
 *          $HEADERS ...
 * -> 1002: $ARGS ...
 *          $HEADERS ...
 *
 * =>:
 *  ARGS:1001
 *          |-> $ARGS ...
 *       1002
 *          |-> $ARGS ...
 *  $HEADERS:1001
 *              |-> $HEADERS ...
 *           1002
 *              |-> $HEADERS ...
 */

// action flag
#define NGX_HTTP_WAF_LOG       0x0001
#define NGX_HTTP_WAF_BLOCK     0x0002

#define ngx_http_waf_action_is_log(flag)      \
    ((flag) & NGX_HTTP_WAF_LOG == NGX_HTTP_WAF_LOG)
#define ngx_http_waf_action_is_block(flag)    \
    ((flag) & NGX_HTTP_WAF_BLOCK == NGX_HTTP_WAF_BLOCK)

// check rule
#define NGX_HTTP_WAF_SC_EQUAL    0x0001
#define NGX_HTTP_WAF_SC_GREATER  0x0002
#define NGX_HTTP_WAF_SC_GEQUAL   0x0003
#define NGX_HTTP_WAF_SC_LESSER   0x0004
#define NGX_HTTP_WAF_SC_LEQUAL   0x0005

#define ngx_http_waf_sc_gt(flag)    \
    ((flag) & NGX_HTTP_WAF_SC_GREATER == NGX_HTTP_WAF_SC_GREATER)
#define ngx_http_waf_sc_ge(flag)    \
    ((flag) & NGX_HTTP_WAF_SC_GEQUAL == NGX_HTTP_WAF_SC_GEQUAL)
#define ngx_http_waf_sc_lt(flag)    \
    ((flag) & NGX_HTTP_WAF_SC_LESSER == NGX_HTTP_WAF_SC_LESSER)
#define ngx_http_waf_sc_le(flag)    \
    ((flag) & NGX_HTTP_WAF_SC_LEQUAL == NGX_HTTP_WAF_SC_LEQUAL)

// matchzone
// general
#define NGX_HTTP_WAF_MZ_G                0x100F
#define NGX_HTTP_WAF_MZ_G_URL            0x0001
#define NGX_HTTP_WAF_MZ_G_ARGS           0x0002
#define NGX_HTTP_WAF_MZ_G_HEADERS        0x0004
#define NGX_HTTP_WAF_MZ_G_BODY           0x0008
#define NGX_HTTP_WAF_MZ_G_RAW_BODY       0x1000

// specify var
#define NGX_HTTP_WAF_MZ_VAR              0x00F0
#define NGX_HTTP_WAF_MZ_VAR_URL          0x0010
#define NGX_HTTP_WAF_MZ_VAR_ARGS         0x0020
#define NGX_HTTP_WAF_MZ_VAR_HEADERS      0x0040
#define NGX_HTTP_WAF_MZ_VAR_BODY         0x0080

// regex var
#define NGX_HTTP_WAF_MZ_X                0x0F00
#define NGX_HTTP_WAF_MZ_X_URL            0x0100
#define NGX_HTTP_WAF_MZ_X_ARGS           0x0200
#define NGX_HTTP_WAF_MZ_X_HEADERS        0x0400
#define NGX_HTTP_WAF_MZ_X_BODY           0x0800

#define NGX_HTTP_WAF_MZ_URL              0x0111
#define NGX_HTTP_WAF_MZ_ARGS             0x0222
#define NGX_HTTP_WAF_MZ_HEADERS          0x0444
#define NGX_HTTP_WAF_MZ_BODY             0x1888

// #define NGX_HTTP_WAF_MZ_NIL           0x2000
// specify match key
#define NGX_HTTP_WAF_MZ_KEY              0x4000
// specify match val
#define NGX_HTTP_WAF_MZ_VAL              0x8000

#define ngx_http_waf_mz_general(flag)           \
    ((flag) & NGX_HTTP_WAF_MZ_G)
#define ngx_http_waf_mz_var(flag)               \
    ((flag) & NGX_HTTP_WAF_MZ_VAR)
#define ngx_http_waf_mz_x(flag)                 \
    ((flag) & NGX_HTTP_WAF_MZ_X)
#define ngx_http_waf_mz_only_key(flag)   \
    ((flag) == NGX_HTTP_WAF_MZ_KEY)
#define ngx_http_waf_mz_key(flag)        \
    ((flag) & NGX_HTTP_WAF_MZ_KEY == NGX_HTTP_WAF_MZ_KEY)
#define ngx_http_waf_mz_val(flag)        \
    ((flag) & NGX_HTTP_WAF_MZ_VAL == NGX_HTTP_WAF_MZ_VAL)
#define ngx_http_waf_mz_set_key_f(flag)  \
    ((flag) |= NGX_HTTP_WAF_MZ_KEY)
#define ngx_http_waf_mz_set_val_f(flag)  \
    ((flag) |= NGX_HTTP_WAF_MZ_VAL)



typedef struct ngx_http_waf_check_s {
    ngx_str_t     tag;
    ngx_uint_t    relation;
    ngx_int_t     score;
    ngx_uint_t    action_flag;
    /* TODO: handler */
} ngx_http_waf_check_t;


typedef struct ngx_http_waf_score_s {
    ngx_str_t              tag;
    ngx_int_t              score;
    ngx_http_waf_check_t  *checker;     /* ngx_http_waf_check_t */
} ngx_http_waf_score_t;


typedef struct ngx_http_waf_public_rule_s {
    ngx_int_t             id;
    ngx_str_t             str;
    ngx_regex_t          *regex;
    ngx_array_t          *scores;       /* ngx_http_waf_score_t. maybe null */
    ngx_uint_t            action_flag;  /* usual handler. maybe 0 */
} ngx_http_waf_public_rule_t;


typedef struct ngx_http_waf_match_zone_s {
    ngx_uint_t    mark;
    ngx_str_t     name;
    ngx_regex_t  *regex;
} ngx_http_waf_match_zone_t;


typedef struct ngx_http_waf_rule_opt_s {
    ngx_http_waf_public_rule_t   *p_rule;
    ngx_array_t                  *wl_ids;    /* ngx_int_t */
    ngx_array_t                  *m_zones;   /* ngx_http_waf_match_zone_t */
} ngx_http_waf_rule_opt_t;


typedef struct ngx_http_waf_rule_s {
    ngx_http_waf_public_rule_t    *p_rule;  /* opt->p_rule */
    ngx_http_waf_match_zone_t     *m_zone;  /* opt->m_zones[x] */
    ngx_array_t                   *wl_zones; /* ngx_http_waf_match_zone_t* */
    unsigned                       invalid:1; /* must match */
} ngx_http_waf_rule_t;


typedef struct ngx_http_waf_whitelist_s {
    ngx_int_t     id;         /* opt->wl_ids[x] */
    ngx_array_t  *url_zones;  /* ngx_http_waf_match_zone_t* */
    ngx_array_t  *args_zones; /* opt->m_zones */
    ngx_array_t  *headers_zones;
    ngx_array_t  *body_zones;
    /* TODO other whitelist*/

    // not specify the match zone.
    unsigned      all_zones:1;
} ngx_http_waf_whitelist_t;


typedef struct {
    ngx_array_t     *headers;  /* ngx_http_waf_rule_t */
    ngx_array_t     *headers_var;
    ngx_array_t     *args;     /* general and regex */
    ngx_array_t     *args_var; /* only var */
    ngx_array_t     *url;
    ngx_array_t     *url_var;
    ngx_array_t     *body;
    ngx_array_t     *body_var;
    ngx_array_t     *raw_body;

    ngx_array_t     *whitelists;  /* ngx_http_waf_whitelist_t */
} ngx_http_waf_main_conf_t;


typedef struct {
    ngx_array_t     *headers;  /* ngx_http_waf_rule_t */
    ngx_array_t     *headers_var;
    ngx_array_t     *args;
    ngx_array_t     *args_var;
    ngx_array_t     *url;
    ngx_array_t     *url_var;
    ngx_array_t     *body;
    ngx_array_t     *body_var;
    ngx_array_t     *raw_body;
    ngx_array_t     *whitelists;  /* ngx_http_waf_whitelist_t */

    ngx_hash_t       headers_var_hash;
    ngx_hash_t       args_var_hash;
    ngx_hash_t       url_var_hash;
    ngx_hash_t       body_var_hash;

    ngx_array_t     *check_rules;  /* ngx_http_waf_check_t */
    ngx_flag_t       libinjection_sql;
    ngx_flag_t       libinjection_xss;
} ngx_http_waf_loc_conf_t;


typedef struct ngx_http_waf_add_rule_s {
    ngx_uint_t   flag;
    ngx_uint_t   offset;
    ngx_uint_t   loc_offset;
    ngx_int_t  (*handler)(ngx_conf_t *cf, ngx_http_waf_public_rule_t *pr,
                          ngx_http_waf_match_zone_t *mz,
                          void *conf, ngx_uint_t offset);
} ngx_http_waf_add_rule_t;


typedef struct ngx_http_waf_add_wl_part_s {
    ngx_uint_t   flag;
    ngx_uint_t   offset;
    ngx_int_t  (*handler)(ngx_conf_t *cf, ngx_http_waf_match_zone_t *mz,
        void *conf, ngx_uint_t offset);
} ngx_http_waf_add_wl_part_t;


typedef struct ngx_http_waf_rule_parser_s ngx_http_waf_rule_parser_t;
typedef ngx_int_t (*ngx_http_waf_rule_item_parse)(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);

struct ngx_http_waf_rule_parser_s {
    ngx_str_t                      prefix;
    ngx_http_waf_rule_item_parse   handler;
} ;


#define ngx_http_waf_match_zone_eq(one, two)    \
    ((one)->mark == (two)->mark && (one)->name.len == (two)->name.len \
    && ngx_strncmp((one)->name.data, (two)->name.data, (one)->name.len) == 0)

static ngx_int_t ngx_array_binary_search(ngx_array_t *a, void *v,
    ngx_int_t (*cmp)(const void *, const void *));
static void *ngx_http_waf_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_waf_main_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_loc_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_check_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_waf_parse_rule_id(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t ngx_http_waf_parse_rule_str(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t ngx_http_waf_parse_rule_rx(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t ngx_http_waf_parse_rule_score(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t ngx_http_waf_parse_rule_msg(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t ngx_http_waf_parse_rule_zone(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t ngx_http_waf_parse_rule_whitelist(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t ngx_http_waf_parse_rule_negative(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t ngx_http_waf_parse_rule_libinj_xss(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t ngx_http_waf_parse_rule_libinj_sql(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);
static ngx_int_t  ngx_http_waf_add_rule_handler(ngx_conf_t *cf,
    ngx_http_waf_public_rule_t *pr, ngx_http_waf_match_zone_t *mz,
    void *conf, ngx_uint_t offset);
static ngx_int_t ngx_http_waf_add_wl_part_handler(ngx_conf_t *cf,
    ngx_http_waf_match_zone_t *mz, void *wl, ngx_uint_t offset);
static ngx_int_t ngx_libc_cdecl ngx_http_waf_whitelist_cmp_id(const void *wl,
    const void *id);
static int ngx_libc_cdecl ngx_http_waf_cmp_whitelist_id(const void *one,
    const void *two);

static ngx_conf_bitmask_t  ngx_http_waf_rule_actions[] = {
    {ngx_string("LOG"),    NGX_HTTP_WAF_LOG},
    {ngx_string("BLOCK"),  NGX_HTTP_WAF_BLOCK},

    {ngx_null_string, 0}
};

static ngx_conf_bitmask_t  ngx_http_waf_rule_zones[] = {
    { ngx_string("URL"),
      NGX_HTTP_WAF_MZ_G_URL },

    { ngx_string("ARGS"),
      NGX_HTTP_WAF_MZ_G_ARGS },

    { ngx_string("@ARGS"),
      (NGX_HTTP_WAF_MZ_G_ARGS|NGX_HTTP_WAF_MZ_KEY) },

    { ngx_string("#ARGS"), 
      (NGX_HTTP_WAF_MZ_G_ARGS|NGX_HTTP_WAF_MZ_VAL) },

    { ngx_string("HEADERS"),
      NGX_HTTP_WAF_MZ_G_HEADERS },

    { ngx_string("@HEADERS"),
      (NGX_HTTP_WAF_MZ_G_HEADERS|NGX_HTTP_WAF_MZ_KEY) },

    { ngx_string("#HEADERS"),
      (NGX_HTTP_WAF_MZ_G_HEADERS|NGX_HTTP_WAF_MZ_VAL) },

    { ngx_string("BODY"),
      NGX_HTTP_WAF_MZ_G_BODY },

    { ngx_string("RAW_BODY"),
      NGX_HTTP_WAF_MZ_G_RAW_BODY },

    { ngx_string("V_URL:"),
      NGX_HTTP_WAF_MZ_VAR_URL },

    { ngx_string("V_ARGS:"),
      NGX_HTTP_WAF_MZ_VAR_ARGS },

    { ngx_string("@V_ARGS:"),
      NGX_HTTP_WAF_MZ_VAR_ARGS|NGX_HTTP_WAF_MZ_KEY },

    { ngx_string("#V_ARGS:"),
      NGX_HTTP_WAF_MZ_VAR_ARGS|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("V_HEADERS:"),
      NGX_HTTP_WAF_MZ_VAR_HEADERS },

    { ngx_string("@V_HEADERS:"),
      NGX_HTTP_WAF_MZ_VAR_HEADERS|NGX_HTTP_WAF_MZ_KEY },

    { ngx_string("#V_HEADERS:"),
      NGX_HTTP_WAF_MZ_VAR_HEADERS|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("V_BODY:"),
      NGX_HTTP_WAF_MZ_VAR_BODY },

    { ngx_string("X_URL:"),
      NGX_HTTP_WAF_MZ_X_URL },

    { ngx_string("X_ARGS:"),
      NGX_HTTP_WAF_MZ_X_ARGS },

    { ngx_string("X_HEADERS:"),
      NGX_HTTP_WAF_MZ_X_HEADERS },

    { ngx_string("X_BODY:"),
      NGX_HTTP_WAF_MZ_X_BODY },

    { ngx_string("NAME"),
      NGX_HTTP_WAF_MZ_KEY },

    { ngx_null_string, 0 }
};



static ngx_http_waf_add_rule_t  ngx_http_waf_conf_add_rules[] = {

    { NGX_HTTP_WAF_MZ_G_URL|NGX_HTTP_WAF_MZ_X_URL,
      offsetof(ngx_http_waf_main_conf_t, url),
      offsetof(ngx_http_waf_loc_conf_t, url),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_G_ARGS|NGX_HTTP_WAF_MZ_X_ARGS,
      offsetof(ngx_http_waf_main_conf_t, args),
      offsetof(ngx_http_waf_loc_conf_t, args),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_G_HEADERS|NGX_HTTP_WAF_MZ_X_HEADERS,
      offsetof(ngx_http_waf_main_conf_t, headers),
      offsetof(ngx_http_waf_loc_conf_t, headers),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_G_BODY,
      offsetof(ngx_http_waf_main_conf_t, body),
      offsetof(ngx_http_waf_loc_conf_t, body),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_G_RAW_BODY,
      offsetof(ngx_http_waf_main_conf_t, raw_body),
      offsetof(ngx_http_waf_loc_conf_t, raw_body),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_VAR_URL,
      offsetof(ngx_http_waf_main_conf_t, url_var),
      offsetof(ngx_http_waf_loc_conf_t, url_var),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_VAR_ARGS,
      offsetof(ngx_http_waf_main_conf_t, args_var),
      offsetof(ngx_http_waf_loc_conf_t, args_var),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_VAR_HEADERS,
      offsetof(ngx_http_waf_main_conf_t, headers_var),
      offsetof(ngx_http_waf_loc_conf_t, headers_var),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_VAR_BODY,
      offsetof(ngx_http_waf_main_conf_t, body_var),
      offsetof(ngx_http_waf_loc_conf_t, body_var),
      ngx_http_waf_add_rule_handler },

    { 0,
      0,
      0,
      NULL }
};


static ngx_http_waf_add_wl_part_t  ngx_http_waf_conf_add_wl[] = {
    { NGX_HTTP_WAF_MZ_URL,
      offsetof(ngx_http_waf_whitelist_t, url_zones),
      ngx_http_waf_add_wl_part_handler },

    { NGX_HTTP_WAF_MZ_ARGS,
      offsetof(ngx_http_waf_whitelist_t, args_zones),
      ngx_http_waf_add_wl_part_handler},

    { NGX_HTTP_WAF_MZ_HEADERS,
      offsetof(ngx_http_waf_whitelist_t, headers_zones),
      ngx_http_waf_add_wl_part_handler},

    {0, 0, NULL}
};

static ngx_http_waf_rule_parser_t  ngx_http_waf_rule_parser[] = {
    {ngx_string("id:"),  ngx_http_waf_parse_rule_id},
    {ngx_string("sc:"),   ngx_http_waf_parse_rule_score},
    {ngx_string("rx:"),  ngx_http_waf_parse_rule_rx},
    {ngx_string("str:"), ngx_http_waf_parse_rule_str},
    {ngx_string("mz:"),  ngx_http_waf_parse_rule_zone},
    {ngx_string("wl:"),  ngx_http_waf_parse_rule_whitelist},
    {ngx_string("msg:"), ngx_http_waf_parse_rule_msg},
    {ngx_string("negative:"),    ngx_http_waf_parse_rule_negative},
    {ngx_string("d:libinj_xss"), ngx_http_waf_parse_rule_libinj_xss},
    {ngx_string("d:libinj_sql"), ngx_http_waf_parse_rule_libinj_sql},

    {ngx_null_string, NULL}
};



static ngx_command_t  ngx_http_waf_commands[] = {

    { ngx_string("public_rule"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_waf_main_rule,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_rule"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
      ngx_http_waf_loc_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("check_rule"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
      ngx_http_waf_check_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      &ngx_http_waf_rule_actions },

    { ngx_string("libinjection_sql"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, libinjection_sql),
      NULL },

    { ngx_string("libinjection_xss"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, libinjection_xss),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_waf_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_waf_create_main_conf,         /* create main configuration */
    ngx_http_waf_init_main_conf,           /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_waf_create_loc_conf,          /* create location configuration */
    ngx_http_waf_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,        /* module context */
    ngx_http_waf_commands,           /* module directives */
    NGX_HTTP_MODULE,                 /* module type */
    NULL,                            /* init master */
    NULL,                            /* init module */
    NULL,                            /* init process */
    NULL,                            /* init thread */
    NULL,                            /* exit thread */
    NULL,                            /* exit process */
    NULL,                            /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_waf_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_main_conf_t));
    if (wmcf == NULL) {
        return NULL;
    }

    return wmcf;
}


static char *
ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    if (wmcf->whitelists == NULL) {
        return NGX_CONF_OK;
    }

    // quick sort the whitelist array
    ngx_qsort(wmcf->whitelists->elts, (size_t)wmcf->whitelists->nelts,
        sizeof(ngx_http_waf_whitelist_t), ngx_http_waf_cmp_whitelist_id);

    return NGX_CONF_OK;
}


static void
ngx_http_waf_print_public_rule(ngx_http_waf_public_rule_t *br)
{
    ngx_uint_t             x;
    ngx_http_waf_score_t  *scs, *sc;

    fprintf(stderr, "public_rule: id:%ld str:%*s regex:%p action_flag: 0x%X\n",
        br->id, (int)br->str.len, br->str.data, br->regex,
        (unsigned int)br->action_flag);

    if (br->scores == NULL) return;

    scs = br->scores->elts;
    for (x = 0; x < br->scores->nelts; x++) {
        sc = &scs[x];
        fprintf(stderr, "    [%u]score %*s %d\n",
            (unsigned int)x, (int)sc->tag.len, sc->tag.data, (int)sc->score);
    }

    return;
}

static void
ngx_http_waf_print_mz(ngx_http_waf_match_zone_t *mz)
{
    if (mz == NULL) return;
    fprintf(stderr, "mz: 0x%lX %*s\n", mz->mark,
        (int)mz->name.len, mz->name.data);
}

static void
ngx_http_waf_print_wlmz_array(ngx_array_t *a, char *s)
{
    ngx_uint_t    x;
    ngx_http_waf_match_zone_t  *mzs;

    fprintf(stderr, "[wl_mz_array:%s:\n", s);
    if (a == NULL) goto end;

    mzs = a->elts;
    for (x = 0; x < a->nelts; x++) {
        ngx_http_waf_print_mz(&mzs[x]);
    }
    end:
    fprintf(stderr, "]\n");
}

static void
ngx_http_waf_print_wl(ngx_http_waf_whitelist_t *wl)
{
    fprintf(stderr, " {wl:%p\n", wl);
    if (wl == NULL) goto end;
    fprintf(stderr, "  id:%ld\n", wl->id);
    ngx_http_waf_print_wlmz_array(wl->headers_zones, "headers_zones");

    end:
    fprintf(stderr, " }\n");
}

static void
ngx_http_waf_print_wl_array(ngx_array_t *a, char *s) {
    ngx_uint_t    x;
    ngx_http_waf_whitelist_t *wls;

    fprintf(stderr, "[%s\n", s);
    if (a == NULL) goto end;

    wls = a->elts;
    for (x = 0; x < a->nelts; x++) {
        ngx_http_waf_print_wl(&wls[x]);
    }

    end:
    fprintf(stderr, "]\n\n");
}

static void
ngx_http_waf_print_rule(ngx_http_waf_rule_t *r)
{
    fprintf(stderr, "{rule:%p\n", r);
    ngx_http_waf_print_public_rule(r->p_rule);
    ngx_http_waf_print_mz(r->m_zone);
    ngx_http_waf_print_wlmz_array(r->wl_zones, "");
    fprintf(stderr, "}\n");
    return;
}

static void
ngx_http_waf_print_rule_array(ngx_array_t *a, char *s)
{
    ngx_uint_t            x;
    ngx_http_waf_rule_t  *rs;

    fprintf(stderr, "\n%s%s\n", "====rule_array===", s);
    if (a == NULL) goto end;

    rs = a->elts;
    for (x = 0; x < a->nelts; x++) {
        ngx_http_waf_print_rule(&rs[x]);
    }

    end:
    fprintf(stderr, "%s%s\n", "----rule_array---", s);
}


static void *
ngx_http_waf_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));
    if (wlcf == NULL) {
        return NULL;
    }

    wlcf->libinjection_sql = NGX_CONF_UNSET;
    wlcf->libinjection_xss = NGX_CONF_UNSET;

    return wlcf;
}


// search whitelist in array.
static ngx_http_waf_whitelist_t *
ngx_http_waf_search_whitelist(ngx_array_t *wl, ngx_int_t id)
{
    ngx_int_t                  i;
    ngx_http_waf_whitelist_t  *a;

    if (wl == NULL) {
        return NULL;
    }

    // TODO: id < 0

    a = wl->elts;
    i = ngx_array_binary_search(wl, &id, ngx_http_waf_whitelist_cmp_id);
    if (i == NGX_ERROR) {
        return NULL;
    }

    return &a[i];
}


// TODO: error
static ngx_int_t
ngx_http_waf_merge_rule_array(ngx_conf_t *cf, ngx_array_t *wl,
    ngx_array_t *prev, ngx_array_t **conf)
{
    ngx_uint_t                     i, j, k;
    ngx_array_t                   *wl_part;
    ngx_http_waf_rule_t           *rule, *prev_rule, *prev_rules;
    ngx_http_waf_whitelist_t      *wl_rule;
    ngx_http_waf_match_zone_t     *wl_zones;

    if (prev == NULL) {
        return NGX_OK;
    }

    if (wl == NULL && *conf == NULL) {
        *conf = prev;
        return NGX_OK;
    }

    if (*conf == NULL) {
        *conf = ngx_array_create(cf->pool, prev->nelts,
            sizeof(ngx_http_waf_rule_t));

        if (*conf == NULL) {
            return NGX_ERROR;
        }
    }

    // the whitelist only affect prev->
    prev_rules = prev->elts;
    for (i = 0; i < prev->nelts; i++) {
        prev_rule = &prev_rules[i];
        wl_rule = ngx_http_waf_search_whitelist(wl, prev_rule->p_rule->id);

        if (wl_rule != NULL) {
            if (wl_rule->all_zones) {
                continue;
            }

            for (j = 0; ngx_http_waf_conf_add_wl[j].flag !=0 ;j++) {
                if (!(prev_rule->m_zone->mark
                    & ngx_http_waf_conf_add_wl[j].flag)) {
                    continue;
                }

                wl_part = *((ngx_array_t**)
                    ((char*)wl_rule + ngx_http_waf_conf_add_wl[j].offset));
                wl_zones = wl_part->elts;
                for (k = 0; k < wl_part->nelts; k++) {
                    if (ngx_http_waf_match_zone_eq(prev_rule->m_zone,
                        &wl_zones[k])) {
                        goto skip_rule;
                    }
                }

                break;
            }
        }

        rule = ngx_array_push(*conf);
        if (rule == NULL) {
            return NGX_ERROR;
        }
        *rule = *prev_rule;

    skip_rule:
        continue;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_array_binary_search(ngx_array_t *a, void *v,
    ngx_int_t (*cmp)(const void *, const void *))
{
    ngx_int_t       l, r, m, rc;
    u_char         *t;

    l = 0;
    r = a->nelts;
    m = -1;

    t = a->elts;
    while (l <= r) {
        m = l + ((r-l) >> 1);
        rc = cmp((void*)(t + m*a->size), v);
        if (rc < 0) {
            l = m + 1;
        } else if (rc > 0) {
            r = m - 1;
        } else {
            return m;
        }
    }

    return NGX_ERROR;
}

static ngx_int_t ngx_libc_cdecl
ngx_http_waf_whitelist_cmp_id(const void *wl, const void *id)
{
    ngx_int_t                 *n;
    ngx_http_waf_whitelist_t  *w;

    n = (ngx_int_t *)id;
    w = (ngx_http_waf_whitelist_t *) wl;

    return w->id - *n;
}


static int ngx_libc_cdecl
ngx_http_waf_cmp_whitelist_id(const void *one, const void *two)
{
    ngx_http_waf_whitelist_t  *first, *second;

    first = (ngx_http_waf_whitelist_t *) one;
    second = (ngx_http_waf_whitelist_t *) two;

    return first->id - second->id;
}


static ngx_int_t
ngx_http_waf_hash_rule_array(ngx_conf_t *cf, ngx_array_t *a, ngx_hash_t *h)
{

    return NGX_OK;
}



/*
 * 白名单不会继承
 * 基础规则会继承并合并
 */
static char *
ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_waf_loc_conf_t    *prev = parent;
    ngx_http_waf_loc_conf_t    *conf = child;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_array_t                *wl_array;  /* whitelist */
    ngx_array_t                *pr_array;  /* parent rules */

    // check location
    if (conf->check_rules == NULL) {
        return NGX_CONF_OK;
    }

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    if (wmcf == NULL) {
        return NGX_CONF_ERROR;
    }

    // TODO: qsort loc->whitelist
    // TODO: conf->whitelist > prev->whitelist > wmcf->whitelist.
    wl_array = prev->whitelists;
    if (conf->whitelists != NULL) {
        ngx_qsort(conf->whitelists->elts, (size_t)conf->whitelists->nelts,
            sizeof(ngx_http_waf_whitelist_t), ngx_http_waf_cmp_whitelist_id);
        wl_array = conf->whitelists;
    }

    // TODO: 
    // if location the prev-> is not null.
    pr_array = wmcf->headers;
    if (prev->headers != NULL) {
        pr_array = prev->headers;
    }

    // TODO attach whitelist zones or skip rule.
    if (ngx_http_waf_merge_rule_array(cf, wl_array, pr_array, &conf->headers)
        != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    fprintf(stderr, "%s\n", "=======merge1=======");

    // TODO: 
    pr_array = wmcf->headers_var;
    if (prev->headers_var != NULL) {
        pr_array = prev->headers_var;
    }

    // TODO attach whitelist zones or skip rule.
    if (ngx_http_waf_merge_rule_array(cf, wl_array, pr_array, &conf->headers_var)
        != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    fprintf(stderr, "%s\n", "=======merge2=======");

    ngx_http_waf_print_rule_array(conf->headers, "conf->headers");
    ngx_http_waf_print_rule_array(conf->headers_var, "conf->headers_var");

    // TODO:

    ngx_http_waf_hash_rule_array(cf, conf->url_var, &conf->url_var_hash);

    return NGX_CONF_OK;
}


static u_char*
ngx_http_waf_score_tag(u_char *b, u_char *e, char *s) {
    u_char *p = b;

    while (p < e) {
        if (ngx_strchr(s, *p) != NULL) {
            return p;
        }
        if (!( (*p >= 'a' && *p <= 'z') || *p == '_' 
            || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') )) {
            return NULL;
        }
        p++;
    }

    return NULL;
}


// parse the rule item
// include public rule and customer zones and whitelist.
static ngx_int_t
ngx_http_waf_parse_rule(ngx_conf_t *cf, ngx_http_waf_rule_opt_t *opt_rule)
{
    ngx_int_t                    res, vailid;
    ngx_str_t                   *value;
    ngx_uint_t                   i, j;
    ngx_http_waf_rule_parser_t  *parser;

    value = cf->args->elts;

    opt_rule->p_rule = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_public_rule_t));
    if (opt_rule->p_rule == NULL) {
        return NGX_ERROR;
    }

    opt_rule->m_zones = ngx_array_create(cf->pool, 2,
        sizeof(ngx_http_waf_match_zone_t));
    if (opt_rule->m_zones == NULL) {
        return NGX_ERROR;
    }

    for(i = 1; i < cf->args->nelts; i++) {
        vailid = 0;
        for (j = 0; ngx_http_waf_rule_parser[j].prefix.data != NULL; j++) {
            parser = &ngx_http_waf_rule_parser[j];
            if (ngx_strncmp(value[i].data, parser->prefix.data,
                parser->prefix.len) == 0) {
                vailid = 1;
                res = parser->handler(cf, &value[i], parser, opt_rule);
                if (res != NGX_OK) {
                    return res;
                }
            }
        }

        if (vailid == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid arguments \"%s\" in \"%s\" directive",
                               value[i].data, value[0].data);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_http_waf_add_rule_handler(ngx_conf_t *cf, ngx_http_waf_public_rule_t *pr,
    ngx_http_waf_match_zone_t *mz, void *conf, ngx_uint_t offset)
{
    char  *p = conf;

    ngx_array_t           **a;
    ngx_http_waf_rule_t    *r;

    // maybe the rule is whitelist.
    if (pr == NULL) {
        return NGX_OK;
    }

    a = (ngx_array_t **)(p + offset);

    if (*a == NULL) {
        *a = ngx_array_create(cf->pool, 3, sizeof(ngx_http_waf_rule_t));
        if (*a == NULL) {
            return NGX_ERROR;
        }
    }

    r = ngx_array_push(*a);
    if (r == NULL) {
        return NGX_ERROR;
    }

    r->m_zone = mz;
    r->p_rule = pr;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_add_wl_part_handler(ngx_conf_t *cf,
    ngx_http_waf_match_zone_t *mz, void *wl, ngx_uint_t offset)
{
    char *p = wl;

    ngx_array_t                **a;
    ngx_http_waf_match_zone_t  *z;

    a = (ngx_array_t **)(p + offset);

    if (*a == NULL) {
        *a = ngx_array_create(cf->pool, 1, sizeof(ngx_http_waf_match_zone_t));
        if (*a == NULL) {
            return NGX_ERROR;
        }
    }

    z = ngx_array_push(*a);
    if (z == NULL) {
        return NGX_ERROR;
    }
    *z = *mz;

    return NGX_OK;
}


//
static ngx_int_t
ngx_http_waf_add_whitelist(ngx_conf_t *cf, ngx_http_waf_rule_opt_t *opt,
    ngx_array_t **a)
{
    ngx_int_t                   *id, rc;
    ngx_uint_t                  i, j, k;
    ngx_http_waf_whitelist_t    *wl;
    ngx_http_waf_match_zone_t   *zones;
    ngx_http_waf_add_wl_part_t  *add_wl;

    if (opt->wl_ids == NULL) return NGX_OK;

    if (*a == NULL) {
        *a = ngx_array_create(cf->pool, 3, sizeof(ngx_http_waf_whitelist_t));
        if (*a == NULL) {
            return NGX_ERROR;
        }
    }

    id = opt->wl_ids->elts;
    for (i = 0; i < opt->wl_ids->nelts; i++) {
        wl = ngx_array_push(*a);
        if (wl == NULL) {
            return NGX_ERROR;
        }

        wl->id = id[i];
        if (opt->m_zones == NULL) {
            wl->all_zones = 1;
            continue;
        }

        zones = opt->m_zones->elts;
        for (j = 0; j < opt->m_zones->nelts; j++) {
            for (k = 0; ngx_http_waf_conf_add_wl[k].flag !=0; k++) {
                add_wl = &ngx_http_waf_conf_add_wl[k];
                if (zones[j].mark & add_wl->flag) {
                    rc = add_wl->handler(cf, &zones[j], wl, add_wl->offset);
                    if (rc != NGX_OK) {
                        return NGX_ERROR;
                    }
                    break;
                }
            }
        }
    }

    return NGX_OK;
}


static char *
ngx_http_waf_main_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                        rc, vailid;
    ngx_uint_t                       i, j;
    ngx_http_waf_main_conf_t        *wmcf = conf;
    ngx_http_waf_rule_opt_t          opt;
    ngx_http_waf_match_zone_t    *zone;

    ngx_memzero(&opt, sizeof(ngx_http_waf_rule_opt_t));
    if (ngx_http_waf_parse_rule(cf, &opt) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // http block is not allowed whitelist.
    if (opt.wl_ids != NULL) {
        return "the whitelist is not allowed here";
    }

    if (opt.m_zones->nelts == 0) {
        return "the rule lack of match zone";
    }

    zone = opt.m_zones->elts;
    for (i = 0; i < opt.m_zones->nelts; i++) {
        vailid = 0;
        for (j = 0; ngx_http_waf_conf_add_rules[j].flag != 0; j++) {
            if (ngx_http_waf_conf_add_rules[j].flag & zone[i].mark) {
                rc = ngx_http_waf_conf_add_rules[j].handler(cf, opt.p_rule,
                &zone[i], wmcf, ngx_http_waf_conf_add_rules[j].offset);

                if (rc != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                vailid = 1;
                break;
            }
        }

        if (vailid == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid mask zone \"%d\"", zone[i].mark);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_loc_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                        rc, vailid;
    ngx_uint_t                       i, j;
    ngx_http_waf_loc_conf_t         *wlcf = conf;
    ngx_http_waf_rule_opt_t          opt;
    ngx_http_waf_match_zone_t       *zone;

    ngx_memzero(&opt, sizeof(ngx_http_waf_rule_opt_t));
    if (ngx_http_waf_parse_rule(cf, &opt) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (opt.wl_ids == NULL && opt.m_zones->nelts == 0) {
        return "lack of match zone";
    }

    // add whitelist
    rc = ngx_http_waf_add_whitelist(cf, &opt, &wlcf->whitelists);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    zone = opt.m_zones->elts;
    for (i = 0; i < opt.m_zones->nelts; i++) {
        vailid = 0;
        for (j = 0; ngx_http_waf_conf_add_rules[j].flag != 0; j++) {
            if (ngx_http_waf_conf_add_rules[j].flag & zone[i].mark) {
                rc = ngx_http_waf_conf_add_rules[j].handler(cf, opt.p_rule,
                &zone[i], wlcf, ngx_http_waf_conf_add_rules[j].loc_offset);

                if (rc != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                vailid = 1;
                break;
            }
        }

        if (vailid == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid mask zone \"%d\"", zone[i].mark);
            return NGX_CONF_ERROR;
        }
    }

    // ngx_http_waf_print_rule_array(wlcf->headers, "wlcf->headers");
    // ngx_http_waf_print_rule_array(wlcf->headers_var, "wlcf->headers_var");
    return NGX_CONF_OK;
}


// "$LABLE >=  4" or "$LABLE>=4"
static ngx_int_t
ngx_http_waf_parse_check(ngx_str_t *itm, ngx_http_waf_check_t *c)
{
    u_char        *p, *s, *e;
    ngx_uint_t    relation = 0;

    e = itm->data + itm->len;
    p = itm->data;

    if (*p != '$') {
        return NGX_ERROR;
    }
    p++;

    // tag. separator: '>' or ' ' or '<'
    s = ngx_http_waf_score_tag(p, e, "> <");
    if (s == NULL) {
        return NGX_ERROR;
    }
    c->tag.data = p;
    c->tag.len  = s - p;

    // relation
    while (*s == ' ') s++;
    if (*s == '>') {
        relation = NGX_HTTP_WAF_SC_GREATER;
    } else if (*s == '<') {
        relation = NGX_HTTP_WAF_SC_LESSER;
    } else {
        return NGX_ERROR;
    }
    s++;
    if (*s == '=') {
        relation |= NGX_HTTP_WAF_SC_EQUAL;
        s++;
    }

    // score
    while(*s == ' ') s++;
    c->score = ngx_atoi(s, e - s);
    if (c->score == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_http_waf_check_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t         *wlcf = conf;
    ngx_http_waf_check_t            *check;
    ngx_conf_bitmask_t              *m;
    ngx_str_t                       *value, *act;
    ngx_int_t                        i;

    value = cf->args->elts;

    if (wlcf->check_rules == NULL) {

        wlcf->check_rules = ngx_array_create(cf->pool, 3,
            sizeof(ngx_http_waf_check_t));
        if (wlcf->check_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    check = ngx_array_push(wlcf->check_rules);
    if (check == NULL) {
        return NGX_CONF_ERROR;
    }

    if (value[1].data[0] == '$') {
        act = &value[2];
        if (ngx_http_waf_parse_check(&value[1], check) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid arguments \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    } else if (value[2].data[0] == '$') {
        act = &value[1];
        if (ngx_http_waf_parse_check(&value[2], check) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid arguments \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    } else {
        return NGX_CONF_ERROR;
    }

    m = cmd->post;
    for (i = 0; m[i].name.len != 0; i++) {
        if (act->len == m[i].name.len 
            && ngx_strncmp(act->data, m[i].name.data, m[i].name.len) == 0) {
            check->action_flag = m[i].mask;

            return NGX_CONF_OK;
        }
    }

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_waf_parse_rule_id(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{
    opt_rule->p_rule->id = ngx_atoi(str->data + parser->prefix.len,
        str->len - parser->prefix.len);

    if (opt_rule->p_rule->id == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid arguments \"%V\"", str);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_str(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{
    opt_rule->p_rule->str.len  = str->len - parser->prefix.len;
    opt_rule->p_rule->str.data = ngx_palloc(cf->pool, opt_rule->p_rule->str.len);
    if (opt_rule->p_rule->str.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(opt_rule->p_rule->str.data, str->data + parser->prefix.len,
        opt_rule->p_rule->str.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_rx(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    opt_rule->p_rule->str.len  = str->len - parser->prefix.len;
    opt_rule->p_rule->str.data = str->data + parser->prefix.len;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    rc.options = NGX_REGEX_CASELESS;
    rc.pattern = opt_rule->p_rule->str;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_ERROR;
    }

    opt_rule->p_rule->regex = rc.regex;

    return NGX_OK;
}


// s:$ATT:3,$ATT2:4,BLOCK,LOG
static ngx_int_t
ngx_http_waf_parse_rule_score(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{
    u_char                *p, *s, *e;
    ngx_int_t              i;
    ngx_http_waf_score_t  *sc;

    if (opt_rule->p_rule->scores == NULL) {
        opt_rule->p_rule->scores = ngx_array_create(cf->pool, 2,
            sizeof(ngx_http_waf_score_t));

        if (opt_rule->p_rule->scores == NULL) {
            return NGX_ERROR;
        }
    }

    e = str->data + str->len;
    p = str->data + parser->prefix.len;

    while (p < e) {
        if (p[0] == '$') {
            p++;
            s = ngx_http_waf_score_tag(p, e, ":");
            if (s == NULL || s - p < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid scores in arguments \"%V\"", str);
                return NGX_ERROR;
            }

            sc = ngx_array_push(opt_rule->p_rule->scores);
            if (sc == NULL) {
                return NGX_ERROR;
            }

            sc->tag.len  = s - p;
            sc->tag.data = ngx_pcalloc(cf->pool, sc->tag.len);
            if (sc->tag.data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(sc->tag.data, p, sc->tag.len);

            p = s + 1;
            s = (u_char *)ngx_strchr(p, ',');
            if (s == NULL) {
                s = e;
            }
            sc->score = ngx_atoi(p, s - p);
            p = s + 1;

            continue;
        }

        for (i = 0; ngx_http_waf_rule_actions[i].name.data != NULL; i++) {
            if (ngx_strncasecmp(p, ngx_http_waf_rule_actions[i].name.data,
                ngx_http_waf_rule_actions[i].name.len) == 0) {

                opt_rule->p_rule->action_flag |=
                    ngx_http_waf_rule_actions[i].mask;
                p += ngx_http_waf_rule_actions[i].name.len;
            }
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid arguments \"%V\"", str);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_waf_parse_rule_msg(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{

    return NGX_OK;
}

// "mz:ARGS|$ARGS_VAR:xxx|$ARGS_VAR_X:xxx|NAME"
// "mz:@ARGS|$ARGS_VAR:#xxx|$ARGS_VAR:@xxx"
static ngx_int_t
ngx_http_waf_parse_rule_zone(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{
    u_char                        *p, *s, *e, errstr[NGX_MAX_CONF_ERRSTR];
    ngx_uint_t                     i, flag, all_mark;
    ngx_regex_compile_t            rc;
    ngx_http_waf_match_zone_t     *zone;

    opt_rule->m_zones = ngx_array_create(cf->pool, 2,
        sizeof(ngx_http_waf_match_zone_t));
    if (opt_rule->m_zones == NULL) {
        return NGX_ERROR;
    }

    e = str->data + str->len;
    p = str->data + parser->prefix.len;
    all_mark = 0;

    while (p < e) {
        if (*p == '|') p++;
        flag = 0;

        for (i = 0; ngx_http_waf_rule_zones[i].name.data != NULL; i++) {
            if (ngx_strncmp(p, ngx_http_waf_rule_zones[i].name.data,
                ngx_http_waf_rule_zones[i].name.len) == 0) {

                flag = ngx_http_waf_rule_zones[i].mask;
                p += ngx_http_waf_rule_zones[i].name.len;
                break;
            }
        }

        if (flag == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone in arguments \"%V\"", str);
            return NGX_ERROR;
        }

        all_mark |= flag;

        // "|NAME"
        if (ngx_http_waf_mz_only_key(flag)) {
            zone = opt_rule->m_zones->elts;
            for (i = 0; i < opt_rule->m_zones->nelts; i++) {
                ngx_http_waf_mz_set_key_f(zone[i].mark);
            }

            goto end;
        }

        zone = ngx_array_push(opt_rule->m_zones);
        if (zone == NULL) {
            return NGX_ERROR;
        }

        zone->mark = flag;


        if (ngx_http_waf_mz_general(flag)) {
            continue;
        }

        if (*(p-1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid custom zone in arguments \"%V\"", str);
            return NGX_ERROR;
        }

        s = (u_char *)ngx_strchr(p, '|');
        if (s == NULL) {
            s = e;
        }

        zone->name.data = ngx_pcalloc(cf->pool, s - p + 1);
        if (zone->name.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(zone->name.data, p, s - p);
        zone->name.len = s - p;

        if (ngx_http_waf_mz_x(flag)) {
            ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
            rc.pool = cf->pool;
            rc.err.len = NGX_MAX_CONF_ERRSTR;
            rc.err.data = errstr;

            rc.options = NGX_REGEX_CASELESS;
            rc.pattern = zone->name;

            if (ngx_regex_compile(&rc) != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
                return NGX_ERROR;
            }

            zone->regex = rc.regex;
        }

        p = s;
    }

    end:

    return NGX_OK;
}


// "wl:x,y..."
// "wl:-x,-y..."
static ngx_int_t
ngx_http_waf_parse_rule_whitelist(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{
    u_char       *p, *s, *e;
    char          minus;
    ngx_int_t    *a, id;

    if (opt_rule->wl_ids == NULL) {
        opt_rule->wl_ids = ngx_array_create(cf->pool, 3, sizeof(ngx_int_t));
        if (opt_rule->wl_ids == NULL) {
            return NGX_ERROR;
        }
    }

    e = str->data + str->len;
    p = str->data + parser->prefix.len;

    while (p < e) {
        minus = 0;
        s = (u_char *)ngx_strchr(p , ',');
        if (s == NULL) {
            s = e;
        }

        if (*p == '-') {
            p++;
            minus = 1;
        }

        id = ngx_atoi(p, s-p);
        if (id == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid whitelisted id in arguments \"%V\"", str);
            return NGX_ERROR;
        }

        a = (ngx_int_t *)ngx_array_push(opt_rule->wl_ids);
        if (a == NULL) {
            return NGX_ERROR;
        }
        p = s + 1;

        if (minus == 1) {
            *a = 0 - id;
            continue;
        }
        *a = id;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_negative(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_libinj_xss(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_libinj_sql(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{

    return NGX_OK;
}


