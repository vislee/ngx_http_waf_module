// Copyright (C) vislee

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


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
#define NGX_HTTP_WAF_MZ_G                0X100F
#define NGX_HTTP_WAF_MZ_G_URL            0x0001
#define NGX_HTTP_WAF_MZ_G_ARGS           0x0002
#define NGX_HTTP_WAF_MZ_G_HEADERS        0x0004
#define NGX_HTTP_WAF_MZ_G_BODY           0x0008
#define NGX_HTTP_WAF_MZ_G_RAW_BODY       0x1000

// specify var
#define NGX_HTTP_WAF_MZ_VAR              0X00F0
#define NGX_HTTP_WAF_MZ_URL_VAR          0x0010
#define NGX_HTTP_WAF_MZ_ARGS_VAR         0x0020
#define NGX_HTTP_WAF_MZ_HEADERS_VAR      0x0040
#define NGX_HTTP_WAF_MZ_BODY_VAR         0x0080
// regex var
#define NGX_HTTP_WAF_MZ_X                0X0F00
#define NGX_HTTP_WAF_MZ_URL_VAR_X        0x0100
#define NGX_HTTP_WAF_MZ_ARGS_VAR_X       0x0200
#define NGX_HTTP_WAF_MZ_HEADERS_VAR_X    0x0400
#define NGX_HTTP_WAF_MZ_BODY_VAR_X       0x0800

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
    ngx_uint_t            id;
    ngx_str_t             str;
    ngx_regex_t          *regex;
    ngx_array_t          *scores;       /* ngx_http_waf_score_t. maybe null */
    ngx_uint_t            action_flag;  /* usual handler. maybe 0 */
    // unsigned              rx:1;
} ngx_http_waf_public_rule_t;


typedef struct ngx_http_waf_customer_zone_s {
    ngx_uint_t    zone_flag;
    ngx_str_t     name;
    ngx_uint_t    name_hash;
    ngx_regex_t  *regex;
    ngx_regex_t  *wl_regex;
} ngx_http_waf_customer_zone_t;


typedef struct ngx_http_waf_rule_opt_s {
    ngx_http_waf_public_rule_t   *p_rule;
    ngx_array_t                  *ids;       /* ngx_int_t */
    ngx_array_t                  *c_zones;   /* ngx_http_waf_customer_zone_t */
} ngx_http_waf_rule_opt_t;


typedef struct ngx_http_waf_rule_s {
    ngx_http_waf_customer_zone_t  *c_zone; /* opt->c_zones[x] */
    ngx_http_waf_public_rule_t    *p_rule; /* opt->p_rule */
} ngx_http_waf_rule_t;


typedef struct ngx_http_waf_whitelist_s {
    ngx_int_t     id;       /* opt->ids[x] */
    ngx_array_t  *c_zones;  /* opt->c_zones */
} ngx_http_waf_whitelist_t;


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
                          ngx_http_waf_customer_zone_t *z,
                          void *conf, ngx_int_t offset);
} ngx_http_waf_add_rule_t;


typedef ngx_int_t (*ngx_http_waf_rule_item_parse)(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt_rule);

typedef struct ngx_http_waf_rule_parser_s {
    ngx_str_t                      prefix;
    ngx_http_waf_rule_item_parse   handler;
} ngx_http_waf_rule_parser_t;

static void *ngx_http_waf_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_waf_main_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_basic_rule(ngx_conf_t *cf, ngx_command_t *cmd,
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
    ngx_http_waf_public_rule_t *pb, ngx_http_waf_customer_zone_t *z,
    void *conf, ngx_int_t offset);
static int ngx_libc_cdecl ngx_http_waf_cmp_whitelist_id(const void *one,
    const void *two);

static ngx_conf_bitmask_t  ngx_http_waf_rule_actions[] = {
    {ngx_string("LOG"),    NGX_HTTP_WAF_LOG},
    {ngx_string("BLOCK"),  NGX_HTTP_WAF_BLOCK},

    {ngx_null_string, 0}
}

static ngx_conf_bitmask_t  ngx_http_waf_rule_zones[] = {
    { ngx_string("URL"),
      NGX_HTTP_WAF_MZ_G_URL },

    { ngx_string("ARGS"),
      NGX_HTTP_WAF_MZ_G_ARGS },
    { ngx_string("@ARGS"),
      (NGX_HTTP_WAF_MZ_G_ARGS | NGX_HTTP_WAF_MZ_KEY) },
    { ngx_string("#ARGS"), 
      (NGX_HTTP_WAF_MZ_G_ARGS | NGX_HTTP_WAF_MZ_VAL) },

    { ngx_string("HEADERS"),
      NGX_HTTP_WAF_MZ_G_HEADERS},
    { ngx_string("@HEADERS"),
      (NGX_HTTP_WAF_MZ_G_HEADERS | NGX_HTTP_WAF_MZ_KEY) },
    { ngx_string("#HEADERS"),
      (NGX_HTTP_WAF_MZ_G_HEADERS | NGX_HTTP_WAF_MZ_VAL) },

    {ngx_string("BODY"),               NGX_HTTP_WAF_MZ_G_BODY},
    {ngx_string("RAW_BODY"),           NGX_HTTP_WAF_MZ_G_RAW_BODY},

    {ngx_string("$URL:"),              NGX_HTTP_WAF_MZ_URL_VAR},
    {ngx_string("$ARGS_VAR:"),         NGX_HTTP_WAF_MZ_ARGS_VAR},
    {ngx_string("$HEADERS_VAR:"),      NGX_HTTP_WAF_MZ_HEADERS_VAR},
    {ngx_string("$BODY_VAR:"),         NGX_HTTP_WAF_MZ_BODY_VAR},

    {ngx_string("$URL_X:"),            NGX_HTTP_WAF_MZ_URL_VAR_X},
    {ngx_string("$ARGS_VAR_X:"),       NGX_HTTP_WAF_MZ_ARGS_VAR_X},
    {ngx_string("$HEADERS_VAR_X:"),    NGX_HTTP_WAF_MZ_HEADERS_VAR_X},
    {ngx_string("$BODY_VAR_X:"),       NGX_HTTP_WAF_MZ_BODY_VAR_X},

    {ngx_string("NAME"),               NGX_HTTP_WAF_MZ_KEY},

    {ngx_null_string, 0}
}



static ngx_http_waf_add_rule_t  ngx_http_waf_conf_add_rules[] = {

    { NGX_HTTP_WAF_MZ_G_URL,
      offsetof(ngx_http_waf_main_conf_t, url),
      offsetof(ngx_http_waf_loc_conf_t, url),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_G_ARGS,
      offsetof(ngx_http_waf_main_conf_t, args),
      offsetof(ngx_http_waf_loc_conf_t, args),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_G_HEADERS,
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

    { NGX_HTTP_WAF_MZ_URL_VAR,
      offsetof(ngx_http_waf_main_conf_t, url_var),
      offsetof(ngx_http_waf_loc_conf_t, url_var),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_ARGS_VAR,
      offsetof(ngx_http_waf_main_conf_t, args_var),
      offsetof(ngx_http_waf_loc_conf_t, args_var),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_HEADERS_VAR,
      offsetof(ngx_http_waf_main_conf_t, headers_var),
      offsetof(ngx_http_waf_loc_conf_t, headers_var),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_BODY_VAR,
      offsetof(ngx_http_waf_main_conf_t, body_var),
      offsetof(ngx_http_waf_loc_conf_t, body_var),
      ngx_http_waf_add_rule_handler },

    { 0,
      0,
      NULL }
}


static ngx_http_waf_rule_parser_t  ngx_http_waf_rule_parser[] = {
    {ngx_string("id:"),  ngx_http_waf_parse_rule_id},
    {ngx_string("s:"),   ngx_http_waf_parse_rule_score},
    {ngx_string("msg:"), ngx_http_waf_parse_rule_msg},
    {ngx_string("rx:"),  ngx_http_waf_parse_rule_rx},
    {ngx_string("str:"), ngx_http_waf_parse_rule_str},
    {ngx_string("mz:"),  ngx_http_waf_parse_rule_zone},
    {ngx_string("wl:"),  ngx_http_waf_parse_rule_whitelist},
    {ngx_string("negative:"),    ngx_http_waf_parse_rule_negative},
    {ngx_string("d:libinj_xss"), ngx_http_waf_parse_rule_libinj_xss},
    {ngx_string("d:libinj_sql"), ngx_http_waf_parse_rule_libinj_sql},

    {ngx_null_string, NULL}
};



static ngx_command_t  ngx_http_waf_commands[] = {

    { ngx_string("main_rule"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_waf_main_rule,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("basic_rule"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
      ngx_http_waf_basic_rule,
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

    ngx_qsort(wmcf->whitelists->elts, (size_t)wmcf->whitelists->nelts,
        sizeof(ngx_http_waf_whitelist_t), ngx_http_waf_cmp_whitelist_id);

    return NGX_CONF_OK;
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

static ngx_int_t
ngx_http_waf_merge_rule_array(ngx_array_t *prev, ngx_array_t *conf) {
    ngx_int_t             i, j;
    ngx_http_waf_rule_t  *rule, *p_rule, *c_rule;

    if (prev == NULL || conf == NULL)  return NGX_OK;

    // TODO: attach whitelist zones or skip rule.

    *p_rule = prev->elts;
    for (i = 0; i < prev->nelts; i++) {
        for (j = 0; j < conf->nelts; j++) {
            c_rule = &conf->elts[j];
            if (p_rule[i].p_rule->id == c_rule->p_rule->id
                && p_rule[i].c_zone->zone_flag == c_rule->c_zone->zone_flag
                && p_rule[i].c_zone->name_hash == c_rule->c_zone->name_hash) {

                // c_rule->white = p_rule[i].white;
                goto skip_merge;
            }

        }

        rule = ngx_array_push(conf);
        if (rule == NULL) {
            return NGX_ERROR;
        }
        rule->c_zone = p_rule[i].c_zone;
        rule->p_rule = p_rule[i].p_rule;
        rule->white  = p_rule[i].white;

        skip_merge:
            continue;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_array_binary_search(ngx_array_t *a, void *v,
    ngx_int_t (*cmp)(const void *, const void *))
{
    ngx_int_t       l, r, m, rc;
    ngx_array_t    *t;

    l = 0;
    r = a->nelts;
    m = -1;

    t = a->elts;
    while (l < r) {
        m = l + ((r-l) >> 1);
        rc = cmp(v, &t[m]);
        if (rc > 0) {
            l = m + 1;
        } else (rc < 0) {
            r = m - 1;
        } else {
            return m;
        }
    }

    return NGX_ERROR;
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

}


static char *
ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_waf_loc_conf_t    *prev = parent;
    ngx_http_waf_loc_conf_t    *conf = child;
    ngx_http_waf_main_conf_t   *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    if (wmcf == NULL) {
        return NGX_CONF_ERROR;
    }

    // TODO qsort loc->whitelist
    ngx_qsort(conf->whitelists->elts, (size_t)conf->whitelists->nelts,
        sizeof(ngx_http_waf_whitelist_t), ngx_http_waf_cmp_whitelist_id);

    // TODO attach whitelist zones or skip rule.
    if (ngx_http_waf_merge_rule_array(parent->url, child->url)
        != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_merge_rule_array(parent->url_var, child->url_var)
        != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_merge_rule_array(wmcf->url, child->url)
        != NGX_OK) {
        return NGX_CONF_ERROR;
    }

}

static char*
ngx_http_waf_score_tag(const u_char *b, const u_char *e, const char *s) {
    u_char *p = b;

    while (p < e) {
        if (ngx_strchr(s, *p) != NULL) {
            return p;
        }
        if (!( (*p >= 'a' && *p <= 'z') || *p == '_' 
            || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') )) {
            return NULL;
        }
    }

    return NULL;
}


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

    opt_rule->c_zones = ngx_array_create(cf->pool, 2,
        sizeof(ngx_http_waf_customer_zone_t));
    if (opt_rule->c_zones == NULL) {
        return NGX_ERROR;
    }

    for(i = 1; i < cf->args->nelts; i++) {
        vailid = 0;
        for (j = 0; ngx_http_waf_rule_parser[j].prefix.data != NULL; j++) {
            parser = ngx_http_waf_rule_parser[j];
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
                               value[0].data, value[i].data);
            return NGX_ERR;
        }
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_http_waf_add_rule_handler(ngx_conf_t *cf, ngx_http_waf_public_rule_t *pb,
    ngx_http_waf_customer_zone_t *z, void *conf, ngx_int_t offset)
{
    char  *p = conf;

    ngx_array_t           **a;
    ngx_http_waf_rule_t    *r;


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

    r->c_zone = z;
    r->p_rule = b;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_add_whitelist(ngx_conf_t *cf, ngx_http_waf_rule_opt_t *opt,
    ngx_array_t **a)
{
    ngx_int_t                  *id;
    ngx_http_waf_whitelist_t   *wl;

    if (opt->ids == NULL) return NGX_OK;

    if (*a == NULL) {
        *a = ngx_array_create(cf->pool, 3, sizeof(ngx_http_waf_whitelist_t));
        if (*a == NULL) {
            return NGX_ERROR;
        }
    }

    id = opt->ids->elts;
    for (i = 0; i < opt->ids->nelts; i++) {
        wl = ngx_array_push(*a);
        if (wl == NULL) {
            return NGX_ERROR;
        }
        wl->id = id[i];
        wl->c_zones = opt->c_zones;
    }

    return NGX_OK;
}

static char *
ngx_http_waf_main_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                        i, j, rc, vailid, *id;
    ngx_http_waf_main_conf_t        *wmcf = conf;
    ngx_http_waf_rule_opt_t          opt;
    ngx_http_waf_customer_zone_t    *zone;

    ngx_memzero(&opt, sizeof(ngx_http_waf_rule_opt_t));
    if (ngx_http_waf_parse_rule(cf, &opt) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (opt.ids == NULL && opt.c_zones.nelts == 0) {
        return "the rule lack of match zone";
    }

    // add whitelist
    rc = ngx_http_waf_add_whitelist(cf, &opt, &wmcf->whitelists);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    zone = opt.c_zones.elts;
    for (i = 0; i < opt.c_zones.nelts; i++) {
        vailid = 0;
        for (j = 0; ngx_http_waf_conf_add_rules[j].flag != 0; j++) {
            if (ngx_http_waf_conf_add_rules[j].flag & zone[i].zone_flag
                == ngx_http_waf_conf_add_rules[j].flag) {

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
                           "invalid mask zone \"%d\"", zone[i].zone_flag);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_basic_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                        i, j, rc, vailid;
    ngx_http_waf_loc_conf_t         *wlcf = conf;
    ngx_http_waf_rule_opt_t          opt;
    ngx_http_waf_customer_zone_t    *zone;

    ngx_memzero(&opt, sizeof(ngx_http_waf_rule_opt_t));
    if (ngx_http_waf_parse_rule(cf, &opt) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (opt.ids == NULL && || opt.c_zones.nelts == 0) {
        return "the rule lack of match zone";
    }

    // add whitelist
    rc = ngx_http_waf_add_whitelist(cf, &opt, &wlcf->whitelists);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    zone = opt.c_zones.elts;
    for (i = 0; i < opt.c_zones.nelts; i++) {
        vailid = 0;
        for (j = 0; ngx_http_waf_conf_add_rules[j].flag != 0; j++) {
            if (ngx_http_waf_conf_add_rules[j].flag & zone[i].zone_flag
                == ngx_http_waf_conf_add_rules[j].flag) {

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
                           "invalid mask zone \"%d\"", zone[i].zone_flag);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


// $LABLE >=  4
// $LABLE<4
static ngx_int_t
ngx_http_waf_parse_check(ngx_str_t *itm, ngx_http_waf_check_t *c)
{
    u_char       *p, *s, *e;
    ngx_uint_t    relation = 0;

    enum {
        sw_start = 0,
        sw_method,
        sw_done
    } state;

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

#if 0
    state = 0;
    for (s = p; s < e; s++) {
        switch (state) {
            case sw_start:
                if (*s == ' ' || *s == '>' || *s == '<') {
                    c->tag.data = p;
                    c->tag.len  = s - p;
                    state = sw_method;
                    p = s;
                    break;
                }

                if (*s < '0' || *s > '9' || *s < 'A' || *s > 'Z'
                    || *s < 'a' || *s > 'z' || *s != '_') {
                    return NGX_ERROR;
                }

                break;
            case sw_method:
                if (*s != '=') {
                    while (*p == ' ') p++;
                    if (s - p > 2) {
                        return NGX_ERROR;
                    }

                    if (*(p+1) == '=') {
                        if (*p == '>') {
                            // >=

                        } else {
                            // <=

                        }
                    } else {
                        if (*p == '>') {
                            // >

                        } else {
                            // <

                        }
                    }
                    p = s;
                    state = sw_done;
                }
                break;
            case sw_done:
                while (*p == ' ') p++;
                c->score = ngx_atoi(p, e - p);
                if (c->score == NGX_ERROR) {
                    return NGX_ERROR;
                }
                s = e;
                break;
        }
    }
#endif

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

    
    if (value[1][0] == '$') {
        act = &value[2];
        if (ngx_http_waf_parse_check(&value[1], check) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid arguments \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    } else if (value[2][0] == '$') {
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
            && ngx_strcmp(act->data, m[i].name.data, m[i].name.len) == 0) {
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
    rc->pool = cf->pool;
    rc->err.len = NGX_MAX_CONF_ERRSTR;
    rc->err.data = errstr;

    rc->options = NGX_REGEX_CASELESS;
    rc->pattern = opt_rule->p_rule->str;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_ERROR;
    }

    opt_rule->regex = rc.regex;
    opt_rule->rx = 1;

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

    if (opt_rule->scores == NULL) {
        opt_rule->scores = ngx_array_create(cf->pool, 2, sizeof(ngx_http_waf_score_t));
        if (opt_rule->scores != NULL) {
            return NGX_ERROR;
        }
    }

    e = str->data + str->len;
    p = str->data + parser->prefix.len;
    while (p < e) {
        if (p[0] == '$') {
            // s = ngx_strchr(p, ':');
            s = ngx_http_waf_score_tag(p, e, ":");
            if (s == NULL || s - p < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid scores in arguments \"%V\"", str);
                return NGX_ERROR;
            }

            sc = ngx_array_push(opt_rule->scores);
            if (sc == NULL) {
                return NGX_ERROR;
            }

            sc->tag.len  = s - p;
            sc->tag.data = ngx_pcalloc(cf->pool, sc->tag.len);
            if (sc->tag.data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(sc->tag.data, p+1, sc->tag.len);

            p = s + 1;
            s = ngx_strchr(p, ',');
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
                p += ngx_http_waf_rule_actions[i].action.len;
            }
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid arguments \"%V\"", str);
        return NGX_ERROR;
    }

    return NGX_OK;
}


// "mz:ARGS|$ARGS_VAR:xxx|$ARGS_VAR_X:xxx|NAME"
// "mz:@ARGS|$ARGS_VAR:#xxx|$ARGS_VAR:@xxx"
//  所有args的头 xxx args的头的val yyy args的头
static ngx_int_t
ngx_http_waf_parse_rule_zone(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{
    u_char                        *p, *s, *e, errstr[NGX_MAX_CONF_ERRSTR];
    ngx_int_t                      i;
    ngx_flag_t                     flag;
    ngx_regex_compile_t            rc;
    ngx_http_waf_customer_zone_t  *zone;


    opt_rule->c_zones = ngx_array_create(cf->pool, 2,
        sizeof(ngx_http_waf_customer_zone_t));
    if (opt_rule->c_zones == NULL) {
        return NGX_ERROR;
    }

    e = str->data + str->len;
    p = str->data + parser->prefix.len;

    while (p < e) {
        if (*p == '|') p++;
        flag = 0;

        for (i = 0; ngx_http_waf_rule_zones[i].name.data != NULL; i++) {
            if (ngx_strncmp(p, ngx_http_waf_rule_zones[i].name.data,
                ngx_http_waf_rule_zones[i].name.len) == 0) {

                p += ngx_http_waf_rule_zones[i].name.len;
                flag = ngx_http_waf_rule_zones[i].mask;
                break;
            }
        }

        if (flag == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone in arguments \"%V\"", str);
            return NGX_ERROR;
        }

        if (ngx_http_waf_mz_only_key(flag)) {
            zone = opt_rule->c_zones->elts;
            for (i = 0; i < opt_rule->c_zones->nelts; i++) {
                ngx_http_waf_mz_set_key_f(zone[i].zone_flag);
            }

            return NGX_OK;
        }

        zone = ngx_array_push(opt_rule->c_zones);
        if (zone == NULL) {
            return NGX_ERROR;
        }

        zone->zone_flag = flag;

        if (ngx_http_waf_mz_general(flag)) {
            continue;
        }

        if (*p != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid custom zone in arguments \"%V\"", str);
            return NGX_ERROR;
        }

        p++;
        if (*p == '@') {
            ngx_http_waf_mz_set_key_f(flag);
            p++;
        } else if (*p == '#') {
            ngx_http_waf_mz_set_val_f(flag);
            p++;
        }

        s = ngx_strchr(p, '|');
        if (s == NULL) {
            s = e;
        }

        zone->name.data = ngx_pcalloc(cf->pool, s - p + 1);
        if (zone->name.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(zone->name.data, s, s - p);
        zone->name.len = s - p;
        zone->name_hash = ngx_hash_key_lc(zone->name.data, zone->name.len);

        if (ngx_http_waf_mz_x(flag)) {
            ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
            rc->pool = cf->pool;
            rc->err.len = NGX_MAX_CONF_ERRSTR;
            rc->err.data = errstr;

            rc->options = NGX_REGEX_CASELESS;
            rc->pattern = zone->name;

            if (ngx_regex_compile(&rc) != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
                return NGX_ERROR;
            }

            zone->regex = rc.regex;
        }

        p = s;
    }

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

    if (opt_rule->ids == NULL) {
        opt_rule->ids = ngx_array_create(cf->pool, 3, sizeof(ngx_int_t));
        if (opt_rule->ids == NULL) {
            return NGX_ERROR;
        }
    }

    e = str->data + str->len;
    p = str->data + parser->prefix.len;

    while (p < e) {
        minus = 0;
        s = ngx_strchr(p , ',');
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

        a = (ngx_int_t *)ngx_array_push(opt_rule->ids);
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







