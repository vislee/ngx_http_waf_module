// Copyright (C) vislee

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef NGX_DEBUG
#include <assert.h>
#endif

/*
 * id 规则的标识，白名单和日志使用。
 * str 字符串匹配
 * s 规则记分
 * z 匹配区域
 * * * * *
 * public_rule id:1001 "str:xxx"  "s:$TT:1,$QQ:2" "z:ARGS|V_HEADERS:cookie";
 * -> ARGS:1001
 * -> V_HEADERS:cookie:1001
 *
 * public_rule id:1002 "str:yyy" "sc:$TT:2,$QQ:2" "z:V_ARGS:foo|V_ARGS:bar|HEADERS";
 * -> V_ARGS:foo: 1002
 * -> HEADERS:1002
 *
 * set_rule "wl:1001,1002" "z:V_ARGS:foo|HEADERS";
 *
 * -> 1001: $ARGS ...
 *          $HEADERS ...
 * -> 1002: $ARGS ...
 *          $HEADERS ...
 *
 * check_rule "$TTT > 5" BLOCK;
 *
 * =>:
 *  ARGS:1001
 *          |-> ARGS
            |->wl: V_ARGS:foo, V_ARGS:bar
 *  HEADERS:1002
 *             |-> HEADERS
 *             |-> wl:HEADERS
 *
 * ARGS_VAR:1002
 *             |-> V_ARGS:foo
 *             |-> V_ARGS:bar
 *             |-> wl:V_ARGS:foo
 * HEADERS_VAR:1001
 *                |-> V_HEADERS:cookie
 *                |-> wl:HEADERS
 * 
 */


// rule status
// action flag
// ngx_http_waf_rule_t->sts
#define NGX_HTTP_WAF_RULE_STS_ACTION   0x000F
#define NGX_HTTP_WAF_RULE_STS_LOG      0x0001
#define NGX_HTTP_WAF_RULE_STS_BLOCK    0x0002
#define NGX_HTTP_WAF_RULE_STS_DROP     0x0004
#define NGX_HTTP_WAF_RULE_STS_ALLOW    0x0008

#define NGX_HTTP_WAF_RULE_STS_SC       0x0010
#define NGX_HTTP_WAF_RULE_STS_WL_X     0x0020

#define NGX_HTTP_WAF_RULE_STS_INVALID     0x1000
#define NGX_HTTP_WAF_RULE_STS_WL_INVALID  0x1100
#define NGX_HTTP_WAF_RULE_STS_SC_INVALID  0x1200


#define ngx_http_waf_rule_invalid(sts)              \
    (((sts) & NGX_HTTP_WAF_RULE_STS_INVALID)        \
        && !((sts) & NGX_HTTP_WAF_RULE_STS_ACTION))
#define ngx_http_waf_rule_wl_x(sts)    \
    ((sts) & NGX_HTTP_WAF_RULE_STS_WL_X)
#define ngx_http_waf_action_is_log(flag)      \
    ((flag) & NGX_HTTP_WAF_RULE_STS_LOG)
#define ngx_http_waf_action_is_block(flag)    \
    ((flag) & NGX_HTTP_WAF_RULE_STS_BLOCK)

// match zone types
// ngx_http_waf_zone_t->flag
// general
#define NGX_HTTP_WAF_MZ_G                0x100F
#define NGX_HTTP_WAF_MZ_G_URL            0x0001
#define NGX_HTTP_WAF_MZ_G_ARGS           0x0002
#define NGX_HTTP_WAF_MZ_G_HEADERS        0x0004
#define NGX_HTTP_WAF_MZ_G_BODY           0x0008
#define NGX_HTTP_WAF_MZ_G_RAW_BODY       0x1000

// specify variable
#define NGX_HTTP_WAF_MZ_VAR              0x00F0
#define NGX_HTTP_WAF_MZ_VAR_URL          0x0010
#define NGX_HTTP_WAF_MZ_VAR_ARGS         0x0020
#define NGX_HTTP_WAF_MZ_VAR_HEADERS      0x0040
#define NGX_HTTP_WAF_MZ_VAR_BODY         0x0080

// regex
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


#define ngx_http_waf_mz_gt(one, two)                            \
    ((one & ((two & NGX_HTTP_WAF_MZ_VAR) >> 4))                 \
    || (one & ((two & NGX_HTTP_WAF_MZ_VAR) >> 8))               \
    || ((one & NGX_HTTP_WAF_MZ_G) == (two & NGX_HTTP_WAF_MZ_G)  \
        && (one & NGX_HTTP_WAF_MZ_G) != 0))
#define ngx_http_waf_mz_general(flag)           \
    ((flag) & NGX_HTTP_WAF_MZ_G)
#define ngx_http_waf_mz_var(flag)               \
    ((flag) & NGX_HTTP_WAF_MZ_VAR)
#define ngx_http_waf_mz_x(flag)                 \
    ((flag) & NGX_HTTP_WAF_MZ_X)
#define ngx_http_waf_mz_only_key(flag)   \
    ((flag) == NGX_HTTP_WAF_MZ_KEY)
#define ngx_http_waf_mz_key(flag)        \
    ((flag) & NGX_HTTP_WAF_MZ_KEY)
#define ngx_http_waf_mz_val(flag)        \
    ((flag) & NGX_HTTP_WAF_MZ_VAL)
#define ngx_http_waf_mz_set_key_f(flag)  \
    ((flag) |= NGX_HTTP_WAF_MZ_KEY)
#define ngx_http_waf_mz_set_val_f(flag)  \
    ((flag) |= NGX_HTTP_WAF_MZ_VAL)


// for check rule
typedef struct ngx_http_waf_check_s {
    ngx_uint_t    idx;          /* the ctx check array index */
    ngx_str_t     tag;          /* check socre tag */
    ngx_int_t     score;        /* the rule socre */
    ngx_int_t     threshold;    /* the check rule threshold*/
    ngx_uint_t    action_flag;  /* the check rule action */
    // TODO: the variable
} ngx_http_waf_check_t;


// the rule score
typedef struct ngx_http_waf_score_s {
    ngx_str_t              tag;
    ngx_int_t              score;
} ngx_http_waf_score_t;


// the rule
typedef struct ngx_http_waf_public_rule_s  ngx_http_waf_public_rule_t;
typedef ngx_int_t (*ngx_http_waf_rule_match_pt)(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
struct ngx_http_waf_public_rule_s {
    ngx_int_t               id;
    ngx_str_t               str;
    ngx_regex_t            *regex;
    ngx_array_t            *scores;  /* ngx_http_waf_score_t. maybe null */

    ngx_http_waf_rule_match_pt  handler;
};


typedef struct ngx_http_waf_zone_s {
    ngx_uint_t    flag;    /* match zone types */
    ngx_str_t     name;    /* the specify variable for match zone */
    ngx_regex_t  *regex;
} ngx_http_waf_zone_t;


// for parse rules
typedef struct ngx_http_waf_rule_opt_s {
    ngx_http_waf_public_rule_t   *p_rule;
    ngx_array_t                  *wl_ids;    /* ngx_int_t */
    ngx_array_t                  *m_zones;   /* ngx_http_waf_zone_t */
} ngx_http_waf_rule_opt_t;


typedef struct ngx_http_waf_rule_s {
    ngx_http_waf_public_rule_t    *p_rule;        /* opt->p_rule */
    ngx_http_waf_zone_t           *m_zone;        /* opt->m_zones[x] */
    ngx_array_t                   *wl_zones;      /* ngx_http_waf_zone_t */
    ngx_array_t                   *score_checks;  /* ngx_http_waf_check_t*/
    // rule status: 
    //include rule invalid, rule action, rule withelist type ...
    ngx_uint_t                     sts;
} ngx_http_waf_rule_t;


typedef struct ngx_http_waf_whitelist_s {
    ngx_int_t     id;         /* opt->wl_ids[x] */
    ngx_array_t  *url_zones;  /* ngx_http_waf_zone_t* */
    ngx_array_t  *args_zones; /* opt->m_zones */
    ngx_array_t  *headers_zones;
    // ngx_array_t  *body_zones;
    /* TODO other whitelist*/
    // not specify the match zone.
    unsigned      all_zones:1;
} ngx_http_waf_whitelist_t;


typedef struct {
    // ngx_http_waf_rule_t
    // general and regex
    ngx_array_t     *url;
    ngx_array_t     *args;
    ngx_array_t     *headers;

    // ngx_http_waf_rule_t
    // specify variable
    ngx_array_t     *url_var;
    ngx_array_t     *args_var;
    ngx_array_t     *headers_var;

    // ngx_array_t     *body;
    // ngx_array_t     *body_var;
    // ngx_array_t     *raw_body;
} ngx_http_waf_main_conf_t;


typedef struct {
    ngx_flag_t       waf_security;
    ngx_flag_t       libinjection_sql;
    ngx_flag_t       libinjection_xss;

    ngx_array_t     *check_rules;  /* ngx_http_waf_check_t */
    ngx_array_t     *whitelists;  /* ngx_http_waf_whitelist_t */

    // ngx_http_waf_rule_t
    // include general and regex rules
    ngx_array_t     *url;
    ngx_array_t     *args;
    ngx_array_t     *headers;
    // ngx_array_t     *body;
    // ngx_array_t     *body_var;
    // ngx_array_t     *raw_body;

    // ngx_http_waf_rule_t
    // only specify variable rules
    ngx_array_t     *url_var;
    ngx_hash_t       url_var_hash;
    ngx_array_t     *args_var;
    ngx_hash_t       args_var_hash;
    ngx_array_t     *headers_var;
    ngx_hash_t       headers_var_hash;

    // ngx_hash_t       body_var_hash;
} ngx_http_waf_loc_conf_t;


typedef struct ngx_http_waf_ctx_s {
    ngx_array_t       *scores; /* ngx_http_waf_score_t */
    ngx_uint_t         status;
} ngx_http_waf_ctx_t;


typedef struct ngx_http_waf_add_rule_s {
    ngx_uint_t   flag;
    ngx_uint_t   offset;
    ngx_uint_t   loc_offset;
    ngx_int_t  (*handler)(ngx_conf_t *cf, ngx_http_waf_public_rule_t *pr,
                          ngx_http_waf_zone_t *mz,
                          void *conf, ngx_uint_t offset);
} ngx_http_waf_add_rule_t;


typedef struct ngx_http_waf_add_wl_part_s {
    ngx_uint_t   flag;
    ngx_uint_t   offset;
    ngx_int_t  (*handler)(ngx_conf_t *cf, ngx_http_waf_zone_t *mz,
        void *conf, ngx_uint_t offset);
} ngx_http_waf_add_wl_part_t;


typedef struct ngx_http_waf_rule_parser_s ngx_http_waf_rule_parser_t;
typedef ngx_int_t (*ngx_http_waf_rule_item_parse_pt)(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);

struct ngx_http_waf_rule_parser_s {
    ngx_str_t                        prefix;
    ngx_http_waf_rule_item_parse_pt  handler;
};


#define ngx_http_waf_match_zone_ge(one, two)    \
    (( ((one)->flag << 4) & (two)->flag) || (((one)->flag << 8) & (two)->flag) \
    || ((one)->flag == (two)->flag && (one)->name.len == (two)->name.len \
    && ngx_strncmp((one)->name.data, (two)->name.data, (one)->name.len) == 0))

static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r);
static void *ngx_http_waf_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
// static char *ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_waf_main_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_loc_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_check_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_waf_parse_rule(ngx_conf_t *cf,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_id(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_str(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_str2(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_rx(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_score(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_msg(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_zone(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_whitelist(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_negative(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_libinj_xss(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_libinj_sql(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);

static ngx_int_t  ngx_http_waf_add_rule_handler(ngx_conf_t *cf,
    ngx_http_waf_public_rule_t *pr, ngx_http_waf_zone_t *mz,
    void *conf, ngx_uint_t offset);
static ngx_int_t ngx_http_waf_add_wl_part_handler(ngx_conf_t *cf,
    ngx_http_waf_zone_t *mz, void *wl, ngx_uint_t offset);
static ngx_int_t ngx_http_waf_rule_str_ct_handler(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
static ngx_int_t ngx_http_waf_rule_str_eq_handler(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
static ngx_int_t ngx_http_waf_rule_str_startwith_handler(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
static ngx_int_t ngx_http_waf_rule_str_endwith_handler(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
static ngx_int_t ngx_http_waf_rule_str_rx_handler(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
static ngx_int_t ngx_libc_cdecl ngx_http_waf_whitelist_cmp_id(const void *wl,
    const void *id);
static int ngx_libc_cdecl ngx_http_waf_cmp_whitelist_id(const void *one,
    const void *two);
static ngx_int_t ngx_array_binary_search(ngx_array_t *a, void *v,
    ngx_int_t (*cmp)(const void *, const void *));

static ngx_conf_bitmask_t  ngx_http_waf_rule_actions[] = {
    {ngx_string("LOG"),    NGX_HTTP_WAF_RULE_STS_LOG},
    {ngx_string("BLOCK"),  NGX_HTTP_WAF_RULE_STS_BLOCK},

    {ngx_null_string, 0}
};


static ngx_conf_bitmask_t  ngx_http_waf_rule_zone_item[] = {
    { ngx_string("URL"),
      NGX_HTTP_WAF_MZ_G_URL|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("V_URL:"),
      NGX_HTTP_WAF_MZ_VAR_URL|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("X_URL:"),
      NGX_HTTP_WAF_MZ_X_URL|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("ARGS"),
      NGX_HTTP_WAF_MZ_G_ARGS|NGX_HTTP_WAF_MZ_KEY|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("@ARGS"),
      (NGX_HTTP_WAF_MZ_G_ARGS|NGX_HTTP_WAF_MZ_KEY) },

    { ngx_string("#ARGS"), 
      (NGX_HTTP_WAF_MZ_G_ARGS|NGX_HTTP_WAF_MZ_VAL) },

    { ngx_string("V_ARGS:"),
      NGX_HTTP_WAF_MZ_VAR_ARGS|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("X_ARGS:"),
      NGX_HTTP_WAF_MZ_X_ARGS|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("HEADERS"),
      NGX_HTTP_WAF_MZ_G_HEADERS|NGX_HTTP_WAF_MZ_KEY|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("@HEADERS"),
      (NGX_HTTP_WAF_MZ_G_HEADERS|NGX_HTTP_WAF_MZ_KEY) },

    { ngx_string("#HEADERS"),
      (NGX_HTTP_WAF_MZ_G_HEADERS|NGX_HTTP_WAF_MZ_VAL) },

    { ngx_string("V_HEADERS:"),
      NGX_HTTP_WAF_MZ_VAR_HEADERS|NGX_HTTP_WAF_MZ_VAL },

    { ngx_string("X_HEADERS:"),
      NGX_HTTP_WAF_MZ_X_HEADERS|NGX_HTTP_WAF_MZ_VAL },

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

    // { NGX_HTTP_WAF_MZ_G_BODY,
    //   offsetof(ngx_http_waf_main_conf_t, body),
    //   offsetof(ngx_http_waf_loc_conf_t, body),
    //   ngx_http_waf_add_rule_handler },

    // { NGX_HTTP_WAF_MZ_G_RAW_BODY,
    //   offsetof(ngx_http_waf_main_conf_t, raw_body),
    //   offsetof(ngx_http_waf_loc_conf_t, raw_body),
    //   ngx_http_waf_add_rule_handler },

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

    // { NGX_HTTP_WAF_MZ_VAR_BODY,
    //   offsetof(ngx_http_waf_main_conf_t, body_var),
    //   offsetof(ngx_http_waf_loc_conf_t, body_var),
    //   ngx_http_waf_add_rule_handler },

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

static ngx_http_waf_rule_parser_t  ngx_http_waf_rule_parser_item[] = {
    {ngx_string("id:"),  ngx_http_waf_parse_rule_id},
    {ngx_string("sc:"),  ngx_http_waf_parse_rule_score},
    {ngx_string("rx:"),  ngx_http_waf_parse_rule_rx},
    {ngx_string("str:"), ngx_http_waf_parse_rule_str},
    {ngx_string("mc:"),  ngx_http_waf_parse_rule_str2},
    {ngx_string("z:"),   ngx_http_waf_parse_rule_zone},
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
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_check_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      &ngx_http_waf_rule_actions },

    { ngx_string("waf_security"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, waf_security),
      NULL },

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
    ngx_http_waf_init,                     /* postconfiguration */

    ngx_http_waf_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

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
    wlcf->waf_security = NGX_CONF_UNSET;

    return wlcf;
}


#if 0
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
#endif

static void
ngx_http_waf_print_public_rule(ngx_http_waf_public_rule_t *br)
{
    ngx_uint_t             x;
    ngx_http_waf_score_t  *scs, *sc;

    fprintf(stderr, "  public_rule: id:%ld str:%*s regex:%p handler: %p\n",
        br->id, (int)br->str.len, br->str.data, br->regex, br->handler);

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
ngx_http_waf_print_check(ngx_http_waf_check_t *c)
{
    if (c == NULL) return;

    fprintf(stderr, "  check: idx:%ld tag:%.*s score:%ld threshold:%ld "
        " action_flag:0x%X\n",
        c->idx, (int)c->tag.len, c->tag.data, c->score, c->threshold,
        (unsigned int)c->action_flag);
}


static void
ngx_http_waf_print_check_array(ngx_array_t *a, char *s)
{
    ngx_uint_t  x;
    ngx_http_waf_check_t *cs;

    fprintf(stderr, "  [check_array:%s\n", s);
    if (a == NULL) goto end;
    cs = a->elts;
    for (x = 0; x < a->nelts; x++) {
        ngx_http_waf_print_check(&cs[x]);
    }

end:
    fprintf(stderr, "  ]\n");

}

static void
ngx_http_waf_print_mz(ngx_http_waf_zone_t *mz)
{
    if (mz == NULL) return;
    fprintf(stderr, "  mz: 0x%lX %*s\n", mz->flag,
        (int)mz->name.len, mz->name.data);
}

static void
ngx_http_waf_print_wlmz_array(ngx_array_t *a, char *s)
{
    ngx_uint_t    x;
    ngx_http_waf_zone_t  *mzs;

    fprintf(stderr, "  [wl_mz_array:%s:\n", s);
    if (a == NULL) goto end;

    mzs = a->elts;
    for (x = 0; x < a->nelts; x++) {
        ngx_http_waf_print_mz(&mzs[x]);
    }
    end:
    fprintf(stderr, "  ]\n");
}

static void
ngx_http_waf_print_wl(ngx_http_waf_whitelist_t *wl)
{
    fprintf(stderr, " {wl:%p\n", wl);
    if (wl == NULL) goto end;
    fprintf(stderr, "  id:%ld\n", wl->id);
    ngx_http_waf_print_wlmz_array(wl->url_zones, "url_zones");
    ngx_http_waf_print_wlmz_array(wl->args_zones, "args_zones");
    ngx_http_waf_print_wlmz_array(wl->headers_zones, "headers_zones");

    end:
    fprintf(stderr, " }\n");
}

static void
ngx_http_waf_print_wl_array(ngx_array_t *a, char *s) {
    ngx_uint_t    x;
    ngx_http_waf_whitelist_t *wls;

    fprintf(stderr, "  [%s\n", s);
    if (a == NULL) goto end;

    wls = a->elts;
    for (x = 0; x < a->nelts; x++) {
        ngx_http_waf_print_wl(&wls[x]);
    }

    end:
    fprintf(stderr, "  ]\n\n");
}

static void
ngx_http_waf_print_rule(ngx_http_waf_rule_t *r)
{
    fprintf(stderr, "{rule:%p\n", r);
    ngx_http_waf_print_public_rule(r->p_rule);
    ngx_http_waf_print_mz(r->m_zone);
    ngx_http_waf_print_wlmz_array(r->wl_zones, "");
    ngx_http_waf_print_check_array(r->score_checks, "");
    fprintf(stderr, "  sts: 0x%X\n", (unsigned int)r->sts);
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
    fprintf(stderr, "%s%s\n\n", "----rule_array---", s);
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
        id = 0;
        i = ngx_array_binary_search(wl, &id, ngx_http_waf_whitelist_cmp_id);
        if (i == NGX_ERROR) {
            return NULL;
        }
    }

    return &a[i];
}


static ngx_int_t
ngx_http_waf_vars_in_hash(ngx_conf_t *cf, ngx_array_t *a,
    ngx_hash_t *h)
{
    ngx_uint_t              i;
    ngx_array_t             vars;
    ngx_hash_key_t         *hk;
    ngx_hash_init_t         hash;
    ngx_http_waf_rule_t    *rules;

    if (ngx_array_init(&vars, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rules = a->elts;
    for (i = 0; i < a->nelts; i++) {
        hk = ngx_array_push(&vars);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = rules[i].m_zone->name;
        hk->key_hash = ngx_hash_key_lc(hk->key.data, hk->key.len);
        hk->value = &rules[i];
    }

    hash.hash = h;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "waf_vars_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, vars.elts, vars.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_merge_rule_array(ngx_conf_t *cf, ngx_array_t *wl,
    ngx_array_t *checks, ngx_array_t *prev, ngx_array_t **conf)
{
    ngx_uint_t                     i, j, k, n;
    ngx_http_waf_rule_t           *prev_rules, *rule, *rules;
    ngx_http_waf_zone_t           *zones;
    ngx_http_waf_score_t          *ss;
    ngx_http_waf_check_t          *cs, *c;
    ngx_http_waf_whitelist_t      *wl_rule;

    if (*conf == NULL) {
        *conf = ngx_array_create(cf->pool, 10,
            sizeof(ngx_http_waf_rule_t));

        if (*conf == NULL) {
            return NGX_ERROR;
        }
    }

    // local config rules size.
    n = (*conf)->nelts;
    // ngx_http_waf_print_rule_array(prev, "prev");
    // merge rule
    if (prev != NULL) {
        prev_rules = prev->elts;
        for (i = 0; i < prev->nelts; i++) {
            rule = ngx_array_push(*conf);
            if (rule == NULL) {
                return NGX_ERROR;
            }

            rule->p_rule = prev_rules[i].p_rule;
            rule->m_zone = prev_rules[i].m_zone;
        }
    }

    // add whitelist zones
    // flag the scores
    rules = (*conf)->elts;
    for (i = 0; i < (*conf)->nelts; i++) {
        rule = &rules[i];

        wl_rule = NULL;
        if (i >= n) {
            // location config rule don't match whitelist.
            wl_rule = ngx_http_waf_search_whitelist(wl, rule->p_rule->id);
        }

        // add whitelist zones
        if (wl_rule != NULL) {
            if (wl_rule->all_zones) {
                rule->sts |= NGX_HTTP_WAF_RULE_STS_WL_INVALID;
            } else {
                for (j = 0; ngx_http_waf_conf_add_wl[j].flag != 0; j++) {

                    if (rule->m_zone->flag & ngx_http_waf_conf_add_wl[j].flag) {

                        rule->wl_zones = *((ngx_array_t**)((char*)wl_rule
                            + ngx_http_waf_conf_add_wl[j].offset));
                        if (rule->wl_zones == NULL
                            || rule->wl_zones->nelts == 0)
                        {
                            break;
                        }

                        zones = rule->wl_zones->elts;
                        for (k = 0; k < rule->wl_zones->nelts; k++) {

                            if (zones[k].regex != NULL) {
                                rule->sts |= NGX_HTTP_WAF_RULE_STS_WL_X;
                            }

                            if (ngx_http_waf_match_zone_ge(&zones[k],
                                rule->m_zone))
                            {
                                rule->sts |= NGX_HTTP_WAF_RULE_STS_WL_INVALID;
                                break;
                            }
                        }

                        break;
                    }
                }
            }
        }

        if (ngx_http_waf_rule_invalid(rule->sts)) {
            continue;
        }

        // socres
        if (rule->p_rule->scores == NULL || rule->p_rule->scores->nelts == 0) {
            rule->sts |= NGX_HTTP_WAF_RULE_STS_BLOCK;
            continue;
        }

        if (checks == NULL || checks->nelts == 0) {
            rule->sts |= NGX_HTTP_WAF_RULE_STS_SC_INVALID;
            continue;
        }

        rule->score_checks = ngx_array_create(cf->pool, 1,
            sizeof(ngx_http_waf_check_t));
        if (rule->score_checks == NULL) {
            return NGX_ERROR;
        }

        ss = rule->p_rule->scores->elts;
        for (j = 0; j < rule->p_rule->scores->nelts; j++) {

            cs = checks->elts;
            for (k = 0; k < checks->nelts; k++) {
                if (cs[k].tag.len != ss[j].tag.len || ngx_strncmp(
                    cs[k].tag.data, ss[j].tag.data, cs[k].tag.len) != 0)
                {
                    continue;
                }

                c = ngx_array_push(rule->score_checks);
                if (c == NULL) {
                    return NGX_ERROR;
                }

                #if (NGX_DEBUG)
                assert(k == cs[k].idx);
                #endif

                c->idx = cs[k].idx;
                c->tag = cs[k].tag;
                c->threshold = cs[k].threshold;
                c->action_flag = cs[k].action_flag;
                c->score = ss[j].score;

                break;
            }

        }
        if (rule->score_checks == NULL || rule->score_checks->nelts == 0) {
            rule->sts |= NGX_HTTP_WAF_RULE_STS_SC_INVALID;
        }

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
    ngx_array_t                *pr_array;  /* parent rules */

    // NGX_CONF_UNSET
    if (1 != conf->waf_security) {
        conf->waf_security = 0;
        return NGX_CONF_OK;
    }

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    if (wmcf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (conf->whitelists != NULL) {
        ngx_qsort(conf->whitelists->elts, (size_t)conf->whitelists->nelts,
            sizeof(ngx_http_waf_whitelist_t), ngx_http_waf_cmp_whitelist_id);
    }

    ngx_http_waf_print_check_array(conf->check_rules, "conf->check_rules");
    ngx_http_waf_print_wl_array(conf->whitelists, "conf->whitelists");

    ngx_http_waf_print_rule_array(conf->url, "@conf->url");
    pr_array = wmcf->url;
    if (prev->url != NULL) {
        pr_array = prev->url;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->url) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_http_waf_print_rule_array(conf->url, "conf->url");


    ngx_http_waf_print_rule_array(conf->url_var, "@conf->url_var");
    pr_array = wmcf->url_var;
    if (prev->url_var != NULL) {
        pr_array = prev->url_var;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->url_var) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_vars_in_hash(cf, conf->url_var,
        &conf->url_var_hash) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_http_waf_print_rule_array(conf->url_var, "conf->url_var");


    ngx_http_waf_print_rule_array(conf->args, "@conf->args");
    pr_array = wmcf->args;
    if (prev->args != NULL) {
        pr_array = prev->args;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->args) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_http_waf_print_rule_array(conf->args, "conf->args");


    ngx_http_waf_print_rule_array(conf->args_var, "@conf->args_var");
    pr_array = wmcf->args_var;
    if (prev->args_var != NULL) {
        pr_array = prev->args_var;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->args_var) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_vars_in_hash(cf, conf->args_var,
        &conf->args_var_hash) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_http_waf_print_rule_array(conf->args_var, "conf->args_var");


    ngx_http_waf_print_rule_array(conf->headers, "@conf->headers");

    pr_array = wmcf->headers;
    if (prev->headers != NULL) {
        pr_array = prev->headers;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->headers) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_http_waf_print_rule_array(conf->headers, "conf->headers");

    ngx_http_waf_print_rule_array(conf->headers_var, "@conf->headers_var");
    pr_array = wmcf->headers_var;
    if (prev->headers_var != NULL) {
        pr_array = prev->headers_var;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->headers_var) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_vars_in_hash(cf, conf->headers_var,
        &conf->headers_var_hash) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_http_waf_print_rule_array(conf->headers_var, "conf->headers_var");

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
ngx_http_waf_parse_rule(ngx_conf_t *cf, ngx_http_waf_rule_opt_t *opt)
{
    ngx_int_t                    rc;
    ngx_str_t                   *value;
    ngx_flag_t                   vailid;
    ngx_uint_t                   i, j;
    ngx_http_waf_rule_parser_t  *parser;

    value = cf->args->elts;

    opt->p_rule = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_public_rule_t));
    if (opt->p_rule == NULL) {
        return NGX_ERROR;
    }

    for(i = 1; i < cf->args->nelts; i++) {
        vailid = 0;
        for (j = 0; ngx_http_waf_rule_parser_item[j].prefix.data != NULL; j++) {
            parser = &ngx_http_waf_rule_parser_item[j];
            if (ngx_strncmp(value[i].data, parser->prefix.data,
                parser->prefix.len) == 0) {
                vailid = 1;
                rc = parser->handler(cf, &value[i], parser, opt);
                if (rc != NGX_OK) {
                    return rc;
                }
            }
        }

        if (!vailid) {
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
    ngx_http_waf_zone_t *mz, void *conf, ngx_uint_t offset)
{
    char  *p = conf;

    ngx_array_t           **a;
    ngx_http_waf_rule_t    *r;

    // maybe the rule is whiterlist.
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
    ngx_http_waf_zone_t *mz, void *wl, ngx_uint_t offset)
{
    char *p = wl;

    ngx_array_t                **a;
    ngx_http_waf_zone_t         *z;

    a = (ngx_array_t **)(p + offset);

    if (*a == NULL) {
        *a = ngx_array_create(cf->pool, 2, sizeof(ngx_http_waf_zone_t));
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
    ngx_flag_t                   vailid;
    ngx_uint_t                   i, j, k;
    ngx_http_waf_whitelist_t    *wl;
    ngx_http_waf_zone_t   *zones;
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
        if (opt->m_zones == NULL || opt->m_zones->nelts == 0) {
            wl->all_zones = 1;
            continue;
        }

        zones = opt->m_zones->elts;
        for (j = 0; j < opt->m_zones->nelts; j++) {
            vailid = 0;
            for (k = 0; ngx_http_waf_conf_add_wl[k].flag !=0; k++) {

                add_wl = &ngx_http_waf_conf_add_wl[k];
                if (!(zones[j].flag & add_wl->flag)) {
                    continue;
                }

                vailid = 1;
                rc = add_wl->handler(cf, &zones[j], wl, add_wl->offset);
                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }
                break;
            }

            if (!vailid) {
                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid whitelist zone");
                 return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static char *
ngx_http_waf_main_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                        rc;
    ngx_flag_t                       vailid;
    ngx_uint_t                       i, j;
    ngx_http_waf_main_conf_t        *wmcf = conf;
    ngx_http_waf_rule_opt_t          opt;
    ngx_http_waf_zone_t       *zone;

    ngx_memzero(&opt, sizeof(ngx_http_waf_rule_opt_t));
    if (ngx_http_waf_parse_rule(cf, &opt) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (opt.p_rule == NULL || opt.p_rule->id == 0) {
        return "the rule error";
    }

    // http block is not allowed whitelist.
    if (opt.wl_ids != NULL) {
        return "the whitelist is not allowed here";
    }

    if (opt.m_zones == NULL || opt.m_zones->nelts == 0) {
        return "the rule lack of zone";
    }

    zone = opt.m_zones->elts;
    for (i = 0; i < opt.m_zones->nelts; i++) {
        vailid = 0;
        for (j = 0; ngx_http_waf_conf_add_rules[j].flag != 0; j++) {
            if (!(ngx_http_waf_conf_add_rules[j].flag & zone[i].flag)) {
                continue;
            }

            rc = ngx_http_waf_conf_add_rules[j].handler(cf, opt.p_rule,
                &zone[i], wmcf, ngx_http_waf_conf_add_rules[j].offset);

            if (rc != NGX_OK) {
                return NGX_CONF_ERROR;
            }
            vailid = 1;
            break;
        }

        if (!vailid) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid mask zone \"%d\"", zone[i].flag);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_loc_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                        rc;
    ngx_flag_t                       vailid;
    ngx_uint_t                       i, j;
    ngx_http_waf_loc_conf_t         *wlcf = conf;
    ngx_http_waf_rule_opt_t          opt;
    ngx_http_waf_zone_t             *zones;

    ngx_memzero(&opt, sizeof(ngx_http_waf_rule_opt_t));
    if (ngx_http_waf_parse_rule(cf, &opt) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (opt.wl_ids == NULL && opt.m_zones->nelts == 0) {
        return "lack of zone";
    }

    // add whitelist
    rc = ngx_http_waf_add_whitelist(cf, &opt, &wlcf->whitelists);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (opt.p_rule->id > 0) {

        zones = opt.m_zones->elts;
        for (i = 0; i < opt.m_zones->nelts; i++) {
            vailid = 0;
            for (j = 0; ngx_http_waf_conf_add_rules[j].flag != 0; j++) {
                if (!(ngx_http_waf_conf_add_rules[j].flag & zones[i].flag)) {
                    continue;
                }

                rc = ngx_http_waf_conf_add_rules[j].handler(cf, opt.p_rule,
                    &zones[i], wlcf, ngx_http_waf_conf_add_rules[j].loc_offset);

                if (rc != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                vailid = 1;
                break;
            }

            if (!vailid) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid mask zone \"%d\"", zones[i].flag);
                return NGX_CONF_ERROR;
            }
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

    e = itm->data + itm->len;
    p = itm->data;

    if (*p != '$') {
        return NGX_ERROR;
    }
    p++;

    // tag. separator: '>' or ' '
    s = ngx_http_waf_score_tag(p, e, "> ");
    if (s == NULL) {
        return NGX_ERROR;
    }
    c->tag.data = p;
    c->tag.len  = s - p;

    while (*s == ' ' || *s == '>') s++;

    c->threshold = ngx_atoi(s, e - s);
    if (c->threshold == NGX_ERROR) {
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
    ngx_str_t                       *value;
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

    check->idx = wlcf->check_rules->nelts - 1;

    if (ngx_http_waf_parse_check(&value[1], check) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid arguments \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    m = cmd->post;
    for (i = 0; m[i].name.len != 0; i++) {
        if (value[2].len == m[i].name.len
            && ngx_strncmp(value[2].data, m[i].name.data, m[i].name.len) == 0) {

            check->action_flag = m[i].mask;
            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid arguments \"%V\"", &value[2]);

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_waf_parse_rule_id(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    opt->p_rule->id = ngx_atoi(str->data + parser->prefix.len,
        str->len - parser->prefix.len);

    if (opt->p_rule->id == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid arguments \"%V\"", str);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_str(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    opt->p_rule->str.len  = str->len - parser->prefix.len;
    opt->p_rule->str.data = ngx_pcalloc(cf->pool,
        opt->p_rule->str.len + 1);
    if (opt->p_rule->str.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(opt->p_rule->str.data, str->data + parser->prefix.len,
        opt->p_rule->str.len);

    return NGX_OK;
}

static ngx_int_t
ngx_http_waf_parse_rule_str2(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    u_char               *p, *e, errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t   rc;


    p = str->data + parser->prefix.len;
    e = str->data + str->len;

    // ct@xyz eq@xyz sw@xyz ew@xyz rx@xyz...
    if (p + 3 >= e || p[2] != '@') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid str in arguments \"%V\"", str);
        return NGX_ERROR;
    }

    opt->p_rule->str.len = e - (p + 3);
    opt->p_rule->str.data = ngx_pcalloc(cf->pool,
        opt->p_rule->str.len + 1);
    if (opt->p_rule->str.data == NULL) {
        return NGX_ERROR;
    }

    if (p[0] == 'c' && p[1] == 't') {
        p += 3;
        ngx_strlow(opt->p_rule->str.data, p, opt->p_rule->str.len);
        opt->p_rule->handler = ngx_http_waf_rule_str_ct_handler;
    } else if (p[0] == 'e' && p[1] == 'q') {
        p += 3;
        ngx_strlow(opt->p_rule->str.data, p, opt->p_rule->str.len);
        opt->p_rule->handler = ngx_http_waf_rule_str_eq_handler;
    } else if (p[0] == 's' && p[1] == 'w') {
        p += 3;
        ngx_strlow(opt->p_rule->str.data, p, opt->p_rule->str.len);
        opt->p_rule->handler = ngx_http_waf_rule_str_startwith_handler;
    } else if (p[0] == 'e' && p[1] == 'w') {
        p += 3;
        ngx_strlow(opt->p_rule->str.data, p, opt->p_rule->str.len);
        opt->p_rule->handler = ngx_http_waf_rule_str_endwith_handler;
    } else if (p[0] == 'r' && p[1] == 'x') {
        p += 3;
        ngx_memcpy(opt->p_rule->str.data, p, opt->p_rule->str.len);
        opt->p_rule->handler = ngx_http_waf_rule_str_rx_handler;
            ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pool = cf->pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        rc.options = NGX_REGEX_CASELESS;
        rc.pattern = opt->p_rule->str;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
            return NGX_ERROR;
        }

        opt->p_rule->regex = rc.regex;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid str in arguments \"%V\"", str);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_rx(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    opt->p_rule->str.len  = str->len - parser->prefix.len;
    opt->p_rule->str.data = str->data + parser->prefix.len;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    rc.options = NGX_REGEX_CASELESS;
    rc.pattern = opt->p_rule->str;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_ERROR;
    }

    opt->p_rule->regex = rc.regex;

    return NGX_OK;
}


// s:$ATT:3,$ATT2:4
static ngx_int_t
ngx_http_waf_parse_rule_score(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    u_char                *p, *s, *e;
    ngx_http_waf_score_t  *sc;

    if (opt->p_rule->scores == NULL) {
        opt->p_rule->scores = ngx_array_create(cf->pool, 2,
            sizeof(ngx_http_waf_score_t));

        if (opt->p_rule->scores == NULL) {
            return NGX_ERROR;
        }
    }

    e = str->data + str->len;
    p = str->data + parser->prefix.len;

    while (p < e) {
        if (*p == ',') p++;

        if (*p++ != '$') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid arguments \"%V\"", str);

            return NGX_ERROR;
        }

        // tag
        s = ngx_http_waf_score_tag(p, e, ":");
        if (s == NULL || s - p <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid scores in arguments \"%V\"", str);
            return NGX_ERROR;
        }

        sc = ngx_array_push(opt->p_rule->scores);
        if (sc == NULL) {
            return NGX_ERROR;
        }

        sc->tag.len  = s - p;
        sc->tag.data = ngx_pcalloc(cf->pool, sc->tag.len);
        if (sc->tag.data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(sc->tag.data, p, sc->tag.len);

        // score
        p = s + 1;
        s = (u_char *)ngx_strchr(p, ',');
        if (s == NULL) {
            s = e;
        }
        sc->score = ngx_atoi(p, s - p);
        p = s + 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_msg(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    return NGX_OK;
}

// URI、V_URI、X_URI
// ARGS V_ARGS X_ARGS
// HEADERS V_HEADERS X_HEADERS
//
// "zone:ARGS|V_HEADERS:xxx|X_HEADERS:xxx"
// "zone:@ARGS'
// "zone:#ARGS'
static ngx_int_t
ngx_http_waf_parse_rule_zone(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    u_char                        *p, *s, *e, errstr[NGX_MAX_CONF_ERRSTR];
    ngx_uint_t                     i, flag, all_flag;
    ngx_regex_compile_t            rc;
    ngx_http_waf_zone_t     *zone;

    if (opt->m_zones == NULL) {
        opt->m_zones = ngx_array_create(cf->pool, 3,
            sizeof(ngx_http_waf_zone_t));
        if (opt->m_zones == NULL) {
            return NGX_ERROR;
        }
    }

    e = str->data + str->len;
    p = str->data + parser->prefix.len;
    all_flag = 0;

    while (p < e) {
        if (*p == '|') p++;
        flag = 0;

        for (i = 0; ngx_http_waf_rule_zone_item[i].name.data != NULL; i++) {
            if (ngx_strncmp(p, ngx_http_waf_rule_zone_item[i].name.data,
                ngx_http_waf_rule_zone_item[i].name.len) == 0) {

                flag = ngx_http_waf_rule_zone_item[i].mask;
                p += ngx_http_waf_rule_zone_item[i].name.len;
                break;
            }
        }

        if (flag == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone in arguments \"%V\"", str);
            return NGX_ERROR;
        }

        if (ngx_http_waf_mz_gt(all_flag, flag)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "wrong zone in arguments \"%V\"", str);
            return NGX_ERROR;
        }

        all_flag |= flag;

        zone = ngx_array_push(opt->m_zones);
        if (zone == NULL) {
            return NGX_ERROR;
        }

        zone->flag = flag;

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

        if (s == p) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "wrong custom zone in arguments \"%V\"", str);
            return NGX_ERROR;
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

    return NGX_OK;
}


// "wl:x,y..."
// "wl:-x,-y..."
static ngx_int_t
ngx_http_waf_parse_rule_whitelist(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    u_char       *p, *s, *e;
    char          minus;
    ngx_int_t    *a, id;

    if (opt->wl_ids == NULL) {
        opt->wl_ids = ngx_array_create(cf->pool, 3, sizeof(ngx_int_t));
        if (opt->wl_ids == NULL) {
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

        a = (ngx_int_t *)ngx_array_push(opt->wl_ids);
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
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_libinj_xss(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_libinj_sql(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{

    return NGX_OK;
}


static void
ngx_http_waf_score_calc(ngx_http_waf_ctx_t *ctx, ngx_http_waf_rule_t *rule)
{
    ngx_uint_t              k, idx;
    ngx_http_waf_score_t   *ss;
    ngx_http_waf_check_t   *cs;

    ctx->status |= (rule->sts & NGX_HTTP_WAF_RULE_STS_ACTION);

    if (ngx_http_waf_action_is_block(ctx->status)) {
        return;
    }

    ss = ctx->scores->elts;
    cs = rule->score_checks->elts;
    for (k = 0; k < rule->score_checks->nelts; k++) {
        idx = cs[k].idx;
        fprintf(stderr, "==== calc %.*s  score: %d\n",
            (int)cs[k].tag.len, cs[k].tag.data, (int)cs[k].score);

        ss[idx].score += cs[k].score;

        fprintf(stderr, "=== the %.*s scores %d \n",
            (int)ss[idx].tag.len, ss[idx].tag.data, (int)ss[idx].score);

        if (ss[idx].score > cs[k].threshold) {
            ctx->status |= cs[k].action_flag;
        }
    }
}


// rule string match handler ...
// return NGX_OK match successful, else NGX_ERROR.
static ngx_int_t
ngx_http_waf_rule_str_ct_handler(ngx_http_waf_public_rule_t *pr,
    ngx_str_t *s)
{
    u_char *p, *e;

    if (s == NULL || s->data == NULL || s->len == 0
        || s->len < pr->str.len) {
        return NGX_ERROR;
    }

    e = s->data + s->len;

    p = ngx_strlcasestrn(s->data, e, pr->str.data, pr->str.len - 1);
    if (p != NULL) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_waf_rule_str_eq_handler(ngx_http_waf_public_rule_t *pr,
    ngx_str_t *s)
{
    if (s == NULL || s->data == NULL || s->len == 0) {
        return NGX_ERROR;
    }

    if (s->len == pr->str.len && ngx_strncasecmp(s->data,
        pr->str.data, s->len) == 0)
    {
        return NGX_OK;
    }

    return NGX_ERROR;
}



static ngx_int_t
ngx_http_waf_rule_str_startwith_handler(ngx_http_waf_public_rule_t *pr,
    ngx_str_t *s)
{
    if (s == NULL || s->data == NULL || s->len == 0) {
        return NGX_ERROR;
    }

    if (s->len > pr->str.len && ngx_strncasecmp(s->data,
        pr->str.data, pr->str.len) == 0)
    {
        return NGX_OK;
    }

    return NGX_ERROR;
}



static ngx_int_t
ngx_http_waf_rule_str_endwith_handler(ngx_http_waf_public_rule_t *pr,
    ngx_str_t *s)
{
    u_char *p;

    if (s == NULL || s->data == NULL || s->len == 0
        || s->len <= pr->str.len)
    {
        return NGX_ERROR;
    }

    p = s->data + s->len - pr->str.len;
    if (ngx_strncasecmp(p, pr->str.data, pr->str.len) == 0) {
        return NGX_OK;
    }

    return NGX_ERROR;
}



static ngx_int_t
ngx_http_waf_rule_str_rx_handler(ngx_http_waf_public_rule_t *pr,
    ngx_str_t *s)
{
    ngx_int_t   n;

    n = ngx_regex_exec(pr->regex, s, NULL, 0);
    if (n == NGX_REGEX_NO_MATCHED) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_waf_rule_str_match(ngx_http_waf_ctx_t *ctx, ngx_http_waf_rule_t *rule,
    ngx_str_t *key, ngx_str_t *val)
{
    // match key
    if (key != NULL && ngx_http_waf_mz_key(rule->m_zone->flag)) {

        if (rule->p_rule->handler(rule->p_rule, key) == NGX_OK) {
            ngx_http_waf_score_calc(ctx, rule);
        }
    }

    // match value
    if (val != NULL && ngx_http_waf_mz_val(rule->m_zone->flag)) {

        if (rule->p_rule->handler(rule->p_rule, val) == NGX_OK) {
            ngx_http_waf_score_calc(ctx, rule);
        }
    }

    return;
}



// exec regex zone
// return NGX_OK matched, else NGX_ERROR.
static ngx_int_t
ngx_http_waf_zone_regex_exec(ngx_http_waf_zone_t *z, ngx_str_t *s)
{
    ngx_int_t     rc;

    if (z->regex == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_regex_exec(z->regex, s, NULL, 0);
    if (rc == NGX_REGEX_NO_MATCHED) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_waf_hash_find(ngx_http_waf_ctx_t *ctx, ngx_hash_t *hash,
    ngx_str_t *key, ngx_str_t *val, ngx_uint_t hk)
{
    ngx_uint_t                    i, k;
    ngx_hash_elt_t               *elt;
    ngx_http_waf_rule_t          *r;
    ngx_http_waf_zone_t          *mzs;


    if (hash->size == 0 || key == NULL || key->len == 0) {
        return;
    }

    if (hk == 0) {
        hk = ngx_hash_key_lc(key->data, key->len);
    }
    elt = hash->buckets[hk % hash->size];

    if (elt == NULL) {
        return;
    }

    while (elt->value) {
        if (key->len != (size_t) elt->len) {
            goto next;
        }

        for (i = 0; i < key->len; i++) {
            if (key->data[i] != elt->name[i]) {
                goto next;
            }
        }

        // TODO:
        r = elt->value;
        if (ngx_http_waf_rule_invalid(r->sts)) {
            goto next;
        }

        if (ngx_http_waf_rule_wl_x(r->sts)) {
            // TODO: whitelist regex
            mzs = r->wl_zones->elts;
            for (k = 0; k < r->wl_zones->nelts; k++) {
                if (ngx_http_waf_zone_regex_exec(&mzs[k], key) == NGX_OK) {
                    goto next;
                }
            }
        }

        ngx_http_waf_rule_str_match(ctx, r, key, val);

    next:

        elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                                               sizeof(void *));
        continue;
    }

    return;
}


static void
ngx_http_waf_score_url(ngx_http_request_t *r, ngx_http_waf_loc_conf_t *wlcf)
{
    ngx_uint_t                    j, k;
    ngx_http_waf_ctx_t           *ctx;
    ngx_http_waf_rule_t          *rules;
    ngx_http_waf_zone_t          *mzs;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score url %V", &r->uri);

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL || ctx->status & NGX_HTTP_WAF_RULE_STS_BLOCK) {
        return;
    }

    rules = wlcf->url->elts;

    ngx_http_waf_hash_find(ctx, &wlcf->url_var_hash,
           &r->uri, &r->uri, 0);

    for (j = 0; j < wlcf->url->nelts; j++) {
        if (ngx_http_waf_rule_invalid(rules[j].sts)) {
            continue;
        }

        if (ngx_http_waf_rule_wl_x(rules[j].sts)) {
            mzs = rules->wl_zones->elts;
            for (k = 0; k < rules->wl_zones->nelts; k++) {
                if (ngx_http_waf_zone_regex_exec(&mzs[k], &r->uri) == NGX_OK) {
                    goto nxt_rule;
                }
            }
        }

        if (ngx_http_waf_mz_general(rules[j].m_zone->flag)) {
            ngx_http_waf_rule_str_match(ctx, &rules[j], NULL, &r->uri);
        } else if (ngx_http_waf_mz_x(rules[j].m_zone->flag)) {
            if (ngx_http_waf_zone_regex_exec(rules[j].m_zone,
                &r->uri) == NGX_OK)
            {
                ngx_http_waf_rule_str_match(ctx, &rules[j], NULL, &r->uri);
            }
        } else {
            assert(1);
        }

    nxt_rule:
        continue;
    }

    return;
}


static void
ngx_http_waf_score_args(ngx_http_request_t *r, ngx_http_waf_loc_conf_t *wlcf)
{
    u_char                       *p, *q, *e, *s;
    u_char                       *val_dst;
    ngx_uint_t                    j, k;
    ngx_str_t                     key, val;
    ngx_http_waf_ctx_t           *ctx;
    ngx_http_waf_rule_t          *rules;
    ngx_http_waf_zone_t          *mzs;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score args %V", &r->args);

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL || ctx->status & NGX_HTTP_WAF_RULE_STS_BLOCK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score args block return");
        return;
    }

    p = r->args.data;
    e = r->args.data + r->args.len;
    q = p;

    s = ngx_pnalloc(r->pool, r->args.len);
    if (s == NULL) {
        return;
    }

    rules = wlcf->args->elts;

    while(p < e) {
        if (*p == '=') {
            key.data = s;
            key.len  = p - q;
            ngx_unescape_uri(&s, &q, (p-q), 0);

            p++;

            q = p;
        } else if (*(p+1) == '&' || p+1 == e) {

            val_dst = s + key.len + 1;
            val.data = val_dst;
            val.len  = p - q + 1;

            ngx_unescape_uri(&val_dst, &q, (p-q+1), 0);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http waf module score args: %V=%V", &key, &val);

            ngx_http_waf_hash_find(ctx, &wlcf->args_var_hash, &key, &val, 0);

            for (j = 0; j < wlcf->args->nelts; j++) {
                if (ngx_http_waf_rule_invalid(rules[j].sts)) {
                    goto nxt_rule;
                }

                if (ngx_http_waf_rule_wl_x(rules[j].sts)) {
                    mzs = rules->wl_zones->elts;
                    for (k = 0; k < rules->wl_zones->nelts; k++) {
                        // TODO: regex
                        if (ngx_http_waf_zone_regex_exec(&mzs[k],
                            &key) == NGX_OK)
                        {
                            goto nxt_rule;
                        }
                    }
                }

                if (ngx_http_waf_mz_x(rules[j].m_zone->flag)
                    && ngx_http_waf_zone_regex_exec(rules[j].m_zone,
                        &key) == NGX_OK)
                {
                    ngx_http_waf_rule_str_match(ctx, &rules[j], &key, &val);
                    goto nxt_rule;
                }

                if(ngx_http_waf_mz_general(rules[j].m_zone->flag)) {

                    ngx_http_waf_rule_str_match(ctx, &rules[j], &key, &val);
                }

            nxt_rule:
                continue;
            }


            p += 2;
            q = p;

        } else {
            p++;
        }
    }

    ngx_pfree(r->pool, s);
    return;
}


static void
ngx_http_waf_score_headers(ngx_http_request_t *r, ngx_http_waf_loc_conf_t *wlcf)
{
    ngx_uint_t                    i, j, k;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_waf_ctx_t           *ctx;
    ngx_http_waf_rule_t          *rules;
    ngx_http_waf_zone_t          *mzs;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score headers");

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL || ctx->status & NGX_HTTP_WAF_RULE_STS_BLOCK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score headers block return");
        return;
    }

    rules = wlcf->headers->elts;
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        // TODO: ngx_hash_find
        ngx_http_waf_hash_find(ctx, &wlcf->headers_var_hash,
            &header[i].key, &header[i].value, header[i].hash);

        for (j = 0; j < wlcf->headers->nelts; j++) {
            if (ngx_http_waf_rule_invalid(rules[j].sts)) {
                // continue;
                goto nxt_rule;
            }

            // wl_zones ngx_http_waf_zone_t
            if (ngx_http_waf_rule_wl_x(rules[j].sts)) {
                mzs = rules->wl_zones->elts;
                for (k = 0; k < rules->wl_zones->nelts; k++) {
                    // TODO: regex
                    if (ngx_http_waf_zone_regex_exec(&mzs[k],
                        &header[i].key) == NGX_OK)
                    {
                        goto nxt_rule;
                    }
                }
            }

            if(ngx_http_waf_mz_general(rules[j].m_zone->flag)) {

                ngx_http_waf_rule_str_match(ctx, &rules[j],
                    &header[i].key, &header[i].value);

            } else if (ngx_http_waf_mz_x(rules[j].m_zone->flag)) {
                // TODO
                if (ngx_http_waf_zone_regex_exec(rules[j].m_zone,
                    &header[i].key) == NGX_OK)
                {
                    ngx_http_waf_rule_str_match(ctx, &rules[j],
                        &header[i].key, &header[i].value);
                }
            } else {
                // impossible doing here.
                fprintf(stderr, "error 11\n");
            }

        nxt_rule:
            continue;
        }


    }
}


static ngx_int_t
ngx_http_waf_check(ngx_http_waf_ctx_t *ctx)
{
    if (ngx_http_waf_action_is_block(ctx->status)) {
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_waf_handler(ngx_http_request_t *r)
{
    ngx_uint_t                  i;
    ngx_http_waf_ctx_t         *ctx;
    ngx_http_waf_check_t       *checks;
    ngx_http_waf_score_t       *sc;
    ngx_http_waf_loc_conf_t    *wlcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module");

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (wlcf == NULL || !wlcf->waf_security) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ctx->scores = ngx_array_create(r->pool, wlcf->check_rules->nelts,
            sizeof(ngx_http_waf_score_t));
        if (ctx->scores == NULL) {
            return NGX_ERROR;
        }

        checks = wlcf->check_rules->elts;
        for (i = 0; i < wlcf->check_rules->nelts; i++) {
            sc = ngx_array_push(ctx->scores);
            if (sc == NULL) {
                return NGX_ERROR;
            }
            sc->tag = checks[i].tag;
            sc->score = 0;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    //TODO:
    ngx_http_waf_score_url(r, wlcf);
    ngx_http_waf_score_args(r, wlcf);
    ngx_http_waf_score_headers(r, wlcf);

    return ngx_http_waf_check(ctx);
}


static ngx_int_t
ngx_http_waf_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_waf_handler;

    return NGX_OK;
}