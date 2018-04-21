// Copyright (C) vislee

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "libinjection/libinjection.h"
#include "libinjection/libinjection_sqli.h"

#ifdef NGX_DEBUG
#include <assert.h>
#endif

/*
 * id 规则的标识，白名单和日志使用。
 * str 字符串匹配
 * sc 规则记分
 * z 匹配区域
 * * * * *
 * security_rule id:1001 "str:xxx"  "s:$TT:1,$QQ:2" "z:ARGS|V_HEADERS:cookie";
 * -> ARGS:1001
 * -> V_HEADERS:cookie:1001
 *
 * security_rule id:1002 "str:yyy" "sc:$TT:2,$QQ:2" "z:V_ARGS:foo|V_ARGS:bar|HEADERS";
 * -> V_ARGS:foo: 1002
 * -> HEADERS:1002
 *
 * security_loc_rule "wl:1001,1002" "z:V_ARGS:foo|HEADERS";
 *
 * -> 1001: $ARGS ...
 *          $HEADERS ...
 * -> 1002: $ARGS ...
 *          $HEADERS ...
 *
 * security_check "$TTT > 5" BLOCK;
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
#define NGX_HTTP_WAF_STS_RULE_ACTION   0x0FF00000
#define NGX_HTTP_WAF_STS_RULE_LOG      0x00100000
#define NGX_HTTP_WAF_STS_RULE_BLOCK    0x00200000
#define NGX_HTTP_WAF_STS_RULE_DROP     0x00400000
#define NGX_HTTP_WAF_STS_RULE_DONE     0x00600000  // (BLOCK|DROP)
// #define NGX_HTTP_WAF_STS_RULE_NULL  0x00800000
// #define NGX_HTTP_WAF_STS_RULE_NULL  0x01800000
// #define NGX_HTTP_WAF_STS_RULE_NULL  0x02800000
#define NGX_HTTP_WAF_STS_RULE_MZ_WL    0x04000000
#define NGX_HTTP_WAF_STS_RULE_VAR      0x08000000

#define NGX_HTTP_WAF_STS_MZ_SIGN            0xF0000000
#define NGX_HTTP_WAF_STS_MZ_COUNT           0x10000000
#define NGX_HTTP_WAF_STS_MZ_KEY             0x20000000
#define NGX_HTTP_WAF_STS_MZ_VAL             0x40000000
#define NGX_HTTP_WAF_STS_MZ_KV              0x60000000
#define NGX_HTTP_WAF_STS_RULE_INVALID       0x80000000
#define NGX_HTTP_WAF_STS_RULE_WL_INVALID    0x80000001
#define NGX_HTTP_WAF_STS_RULE_SC_INVALID    0x80000002

// NGX_HTTP_WAF_STS_MZ_KEY & NGX_HTTP_WAF_STS_RULE_MZ_WL
#define NGX_HTTP_WAF_STS_RULE_MZ_KEY_WL     0x24000000
// NGX_HTTP_WAF_STS_MZ_VAL & NGX_HTTP_WAF_STS_RULE_MZ_WL
#define NGX_HTTP_WAF_STS_RULE_MZ_VAL_WL     0x44000000


#define ngx_http_waf_ctx_copy_act(dst_act, src_act) \
    ((dst_act) |= (src_act) & NGX_HTTP_WAF_STS_RULE_ACTION)
#define ngx_http_waf_wl_copy_mz(dst_mz, src_mz)     \
    (dst_mz) |= (NGX_HTTP_WAF_STS_RULE_MZ_WL        \
                | ((src_mz) & NGX_HTTP_WAF_STS_MZ_KV));

#define ngx_http_waf_rule_invalid(sts)              \
    ((sts) & NGX_HTTP_WAF_STS_RULE_INVALID)
#define ngx_http_waf_rule_set_wl_invalid(sts)       \
    ((sts) |= NGX_HTTP_WAF_STS_RULE_WL_INVALID)
#define ngx_http_waf_rule_set_sc_invalid(sts)       \
    ((sts) |= NGX_HTTP_WAF_STS_RULE_SC_INVALID)

#define ngx_http_waf_rule_wl_mz_key(sts)            \
    ((sts) & NGX_HTTP_WAF_STS_RULE_MZ_KEY_WL)
#define ngx_http_waf_rule_wl_mz_val(sts)            \
    ((sts) & NGX_HTTP_WAF_STS_RULE_MZ_VAL_WL)
#define ngx_http_waf_score_is_done(flag)            \
    ((flag) & NGX_HTTP_WAF_STS_RULE_DONE)

#define ngx_http_waf_sts_has_block(flag)            \
    ((flag) & NGX_HTTP_WAF_STS_RULE_BLOCK)
#define ngx_http_waf_sts_act_set_block(flag)        \
    ((flag) |= NGX_HTTP_WAF_STS_RULE_BLOCK)

#define ngx_http_waf_sts_has_drop(flag)             \
    ((flag) & NGX_HTTP_WAF_STS_RULE_DROP)

#define ngx_http_waf_sts_has_var(flag)              \
    ((flag) & NGX_HTTP_WAF_STS_RULE_VAR)

#define ngx_http_waf_act_set_var_block(flag)        \
    ((flag) |= (NGX_HTTP_WAF_STS_RULE_BLOCK | NGX_HTTP_WAF_STS_RULE_VAR))


// 0xFFFFF
// match zone types
// ngx_http_waf_zone_t->flag
// general
#define NGX_HTTP_WAF_MZ_G                0x0300F
#define NGX_HTTP_WAF_MZ_G_URL            0x00001
#define NGX_HTTP_WAF_MZ_G_ARGS           0x00002
#define NGX_HTTP_WAF_MZ_G_HEADERS        0x00004
#define NGX_HTTP_WAF_MZ_G_BODY           0x00008
#define NGX_HTTP_WAF_MZ_G_RAW_BODY       0x01000
// multipart/form-data
#define NGX_HTTP_WAF_MZ_G_FILE_BODY      0x02000

// specify variable
#define NGX_HTTP_WAF_MZ_VAR              0x000F0
#define NGX_HTTP_WAF_MZ_VAR_URL          0x00010
#define NGX_HTTP_WAF_MZ_VAR_ARGS         0x00020
#define NGX_HTTP_WAF_MZ_VAR_HEADERS      0x00040
// for form-xxx
#define NGX_HTTP_WAF_MZ_VAR_BODY         0x00080

// regex
#define NGX_HTTP_WAF_MZ_X                0x00F00
#define NGX_HTTP_WAF_MZ_X_URL            0x00100
#define NGX_HTTP_WAF_MZ_X_ARGS           0x00200
#define NGX_HTTP_WAF_MZ_X_HEADERS        0x00400
// for form-xxx
#define NGX_HTTP_WAF_MZ_X_BODY           0x00800

#define NGX_HTTP_WAF_MZ_URL              0x00111
#define NGX_HTTP_WAF_MZ_ARGS             0x00222
#define NGX_HTTP_WAF_MZ_HEADERS          0x00444
#define NGX_HTTP_WAF_MZ_BODY             0x01888
#define NGX_HTTP_WAF_MZ_G_FILE_BODY      0x02000


#define ngx_http_waf_mz_gt(one, two)                            \
    ((one & ((two & NGX_HTTP_WAF_MZ_VAR) >> 4))                 \
    || (one & ((two & NGX_HTTP_WAF_MZ_VAR) >> 8))               \
    || ((one & NGX_HTTP_WAF_MZ_G) == (two & NGX_HTTP_WAF_MZ_G)  \
        && (one & NGX_HTTP_WAF_MZ_G) != 0))

#define ngx_http_waf_mz_is_general(flag)           \
    ((flag) & NGX_HTTP_WAF_MZ_G)
#define ngx_http_waf_mz_is_regex(flag)             \
    ((flag) & NGX_HTTP_WAF_MZ_X)
#define ngx_http_waf_mz_key(flag)        \
    ((flag) & NGX_HTTP_WAF_STS_MZ_KEY)
#define ngx_http_waf_mz_val(flag)        \
    ((flag) & NGX_HTTP_WAF_STS_MZ_VAL)



typedef struct ngx_http_waf_rule_s  ngx_http_waf_rule_t;
typedef struct ngx_http_waf_public_rule_s  ngx_http_waf_public_rule_t;
typedef ngx_int_t (*ngx_http_waf_rule_match_pt)(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);

// for check rule
typedef struct ngx_http_waf_check_s {
    ngx_uint_t    idx;          /* the ctx check array index */
    ngx_str_t     tag;          /* check socre tag */
    ngx_int_t     score;        /* the rule socre */
    ngx_int_t     threshold;    /* the check rule threshold*/
    ngx_uint_t    action_flag;  /* the check rule action */
} ngx_http_waf_check_t;


typedef struct ngx_http_waf_log_ctx_s {
    ngx_str_t               str;
    ngx_http_waf_rule_t    *rule;
    ngx_int_t               score;
} ngx_http_waf_log_ctx_t;


// the rule score
typedef struct ngx_http_waf_score_s {
    ngx_str_t                tag;
    ngx_int_t                score;
    ngx_array_t             *log_ctx;  /* ngx_http_waf_log_ctx_t */
} ngx_http_waf_score_t;


// the rule
struct ngx_http_waf_public_rule_s {
    ngx_int_t               id;
    ngx_str_t               str;
    ngx_regex_t            *regex;
    ngx_array_t            *scores;  /* ngx_http_waf_score_t. maybe null */

    // TODO: decode_handler
    ngx_http_waf_rule_match_pt  handler;
};


typedef struct ngx_http_waf_zone_s {
    ngx_uint_t    flag;    /* match zone types */
    ngx_str_t     name;    /* the specify variable for match zone */
    ngx_regex_t  *regex;
    // ngx_str_t     spec_url_suffix;  // TODO
} ngx_http_waf_zone_t;


// for parse rules
typedef struct ngx_http_waf_rule_opt_s {
    ngx_http_waf_public_rule_t   *p_rule;
    ngx_array_t                  *wl_ids;    /* ngx_int_t */
    ngx_array_t                  *m_zones;   /* ngx_http_waf_zone_t */
} ngx_http_waf_rule_opt_t;


struct ngx_http_waf_rule_s {
    ngx_http_waf_public_rule_t    *p_rule;        /* opt->p_rule */
    ngx_http_waf_zone_t           *m_zone;        /* opt->m_zones[x] */
    ngx_array_t                   *wl_zones;      /* ngx_http_waf_zone_t */
    ngx_array_t                   *score_checks;  /* ngx_http_waf_check_t*/
    // rule status: 
    //include rule invalid, rule action, rule withelist type ...
    ngx_uint_t                     sts;
};


typedef struct ngx_http_waf_whitelist_s {
    ngx_int_t     id;         /* opt->wl_ids[x] */
    ngx_array_t  *url_zones;  /* ngx_http_waf_zone_t* */
    ngx_array_t  *args_zones; /* opt->m_zones */
    ngx_array_t  *headers_zones;
    ngx_array_t  *body_zones;
    ngx_array_t  *body_file_zones;
    // not specify the match zone.
    unsigned      all_zones:1;
} ngx_http_waf_whitelist_t;


typedef struct {
    // ngx_http_waf_rule_t
    // general and regex
    ngx_array_t     *url;
    ngx_array_t     *args;
    ngx_array_t     *headers;
    ngx_array_t     *body;
    ngx_array_t     *raw_body;
    ngx_array_t     *body_file;

    // ngx_http_waf_rule_t
    // specify variable
    ngx_array_t     *url_var;
    ngx_array_t     *args_var;
    ngx_array_t     *headers_var;
    ngx_array_t     *body_var;
} ngx_http_waf_main_conf_t;


typedef struct {
    ngx_flag_t          security_waf;
    ngx_uint_t          log_off;
    ngx_open_file_t    *log_file;

    ngx_array_t        *check_rules;  /* ngx_http_waf_check_t */
    ngx_array_t        *whitelists;  /* ngx_http_waf_whitelist_t */

    // ngx_http_waf_rule_t
    // include general and regex rules
    ngx_array_t        *url;
    ngx_array_t        *args;
    ngx_array_t        *headers;
    ngx_array_t        *body;
    ngx_array_t        *body_file;
    ngx_array_t        *raw_body;

    // ngx_http_waf_rule_t
    // only specify variable rules
    ngx_array_t        *url_var;
    ngx_hash_t          url_var_hash;
    ngx_array_t        *args_var;
    ngx_hash_t          args_var_hash;
    ngx_array_t        *headers_var;
    ngx_hash_t          headers_var_hash;
    ngx_array_t        *body_var;
    ngx_hash_t          body_var_hash;
} ngx_http_waf_loc_conf_t;



typedef struct ngx_http_waf_ctx_s {
    ngx_array_t             *scores; /* ngx_http_waf_score_t */
    ngx_http_waf_log_ctx_t  *logc;
    ngx_uint_t               status;
    unsigned                 wait_body:1;
    unsigned                 check_done:1;
    unsigned                 interrupt:1;
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


#define ngx_http_waf_mz_ge(one, two)  (                               \
    ( (((one)->flag&NGX_HTTP_WAF_STS_MZ_KV)      \
        & ((two)->flag&NGX_HTTP_WAF_STS_MZ_KV))                       \
    && (((one)->flag&NGX_HTTP_WAF_STS_MZ_KV)     \
        >= ((two)->flag&NGX_HTTP_WAF_STS_MZ_KV))                      \
    && ((((one)->flag<<4)&(two)->flag) || (((one)->flag<<8)&(two)->flag)) )   \
    || ( ((one)->flag == (two)->flag) && (one)->name.len == (two)->name.len   \
    && ngx_strncmp((one)->name.data, (two)->name.data, (one)->name.len) == 0 )\
)
#define ngx_http_waf_wl_mz(one, two) (                              \
    (((one)->flag & NGX_HTTP_WAF_MZ_G) == ((two)->flag & NGX_HTTP_WAF_MZ_G))  \
    && (((one)->flag & NGX_HTTP_WAF_STS_MZ_KV) != NGX_HTTP_WAF_STS_MZ_KV)     \
    && (((two)->flag & NGX_HTTP_WAF_STS_MZ_KV) == NGX_HTTP_WAF_STS_MZ_KV)     \
)

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
static char *ngx_http_waf_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_waf_parse_rule(ngx_conf_t *cf,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_id(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_str(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_score(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_note(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_zone(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_whitelist(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t ngx_http_waf_parse_rule_libinj(ngx_conf_t *cf,
    ngx_str_t *str, ngx_http_waf_rule_parser_t *parser,
    ngx_http_waf_rule_opt_t *opt);
static ngx_int_t  ngx_http_waf_add_rule_handler(ngx_conf_t *cf,
    ngx_http_waf_public_rule_t *pr, ngx_http_waf_zone_t *mz,
    void *conf, ngx_uint_t offset);
static ngx_int_t ngx_http_waf_add_wl_part_handler(ngx_conf_t *cf,
    ngx_http_waf_zone_t *mz, void *wl, ngx_uint_t offset);
static ngx_int_t ngx_http_waf_rule_str_ge_handler(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
static ngx_int_t ngx_http_waf_rule_str_le_handler(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
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
static ngx_int_t ngx_http_waf_rule_str_sqli_handler(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
static ngx_int_t ngx_http_waf_rule_str_xss_handler(
    ngx_http_waf_public_rule_t *pr, ngx_str_t *s);
static ngx_int_t ngx_http_waf_check_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_conf_bitmask_t  ngx_http_waf_rule_actions[] = {
    {ngx_string("LOG"),    NGX_HTTP_WAF_STS_RULE_LOG},
    {ngx_string("BLOCK"),  NGX_HTTP_WAF_STS_RULE_BLOCK},
    {ngx_string("DROP"),   NGX_HTTP_WAF_STS_RULE_DROP},

    {ngx_null_string, 0}
};


static ngx_conf_bitmask_t  ngx_http_waf_rule_zone_item[] = {
    { ngx_string("URL"),
      NGX_HTTP_WAF_MZ_G_URL|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("#URL"),
      NGX_HTTP_WAF_MZ_G_URL|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("V_URL:"),
      NGX_HTTP_WAF_MZ_VAR_URL|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("X_URL:"),
      NGX_HTTP_WAF_MZ_X_URL|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("ARGS"),
      NGX_HTTP_WAF_MZ_G_ARGS|NGX_HTTP_WAF_STS_MZ_KV },

    { ngx_string("@ARGS"),
      (NGX_HTTP_WAF_MZ_G_ARGS|NGX_HTTP_WAF_STS_MZ_KEY) },

    { ngx_string("#ARGS"), 
      (NGX_HTTP_WAF_MZ_G_ARGS|NGX_HTTP_WAF_STS_MZ_VAL) },

    // TODO: %ARGS args count.

    { ngx_string("V_ARGS:"),
      NGX_HTTP_WAF_MZ_VAR_ARGS|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("X_ARGS:"),
      NGX_HTTP_WAF_MZ_X_ARGS|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("HEADERS"),
      NGX_HTTP_WAF_MZ_G_HEADERS|NGX_HTTP_WAF_STS_MZ_KV },

    { ngx_string("@HEADERS"),
      (NGX_HTTP_WAF_MZ_G_HEADERS|NGX_HTTP_WAF_STS_MZ_KEY) },

    { ngx_string("#HEADERS"),
      (NGX_HTTP_WAF_MZ_G_HEADERS|NGX_HTTP_WAF_STS_MZ_VAL) },

    { ngx_string("V_HEADERS:"),
      NGX_HTTP_WAF_MZ_VAR_HEADERS|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("X_HEADERS:"),
      NGX_HTTP_WAF_MZ_X_HEADERS|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("BODY"),
      NGX_HTTP_WAF_MZ_G_BODY|NGX_HTTP_WAF_STS_MZ_KV },

    { ngx_string("@BODY"),
      NGX_HTTP_WAF_MZ_G_BODY|NGX_HTTP_WAF_STS_MZ_KEY },

    { ngx_string("#BODY"),
      NGX_HTTP_WAF_MZ_G_BODY|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("#RAW_BODY"),
      NGX_HTTP_WAF_MZ_G_RAW_BODY|NGX_HTTP_WAF_STS_MZ_VAL },

    // TODO: file
    { ngx_string("#FILE"),
      NGX_HTTP_WAF_MZ_G_FILE_BODY|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("V_BODY:"),
      NGX_HTTP_WAF_MZ_VAR_BODY|NGX_HTTP_WAF_STS_MZ_VAL },

    { ngx_string("X_BODY:"),
      NGX_HTTP_WAF_MZ_X_BODY|NGX_HTTP_WAF_STS_MZ_VAL },

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

    { NGX_HTTP_WAF_MZ_G_BODY|NGX_HTTP_WAF_MZ_X_BODY,
      offsetof(ngx_http_waf_main_conf_t, body),
      offsetof(ngx_http_waf_loc_conf_t, body),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_G_RAW_BODY,
      offsetof(ngx_http_waf_main_conf_t, raw_body),
      offsetof(ngx_http_waf_loc_conf_t, raw_body),
      ngx_http_waf_add_rule_handler },

    { NGX_HTTP_WAF_MZ_G_FILE_BODY,
      offsetof(ngx_http_waf_main_conf_t, body_file),
      offsetof(ngx_http_waf_loc_conf_t, body_file),
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

    { NGX_HTTP_WAF_MZ_BODY,
      offsetof(ngx_http_waf_whitelist_t, body_zones),
      ngx_http_waf_add_wl_part_handler},

      { NGX_HTTP_WAF_MZ_G_FILE_BODY,
      offsetof(ngx_http_waf_whitelist_t, body_file_zones),
      ngx_http_waf_add_wl_part_handler},

    {0, 0, NULL}
};


static ngx_http_waf_rule_parser_t  ngx_http_waf_rule_parser_item[] = {
    {ngx_string("id:"),     ngx_http_waf_parse_rule_id},
    {ngx_string("s:"),      ngx_http_waf_parse_rule_score},
    {ngx_string("str:"),    ngx_http_waf_parse_rule_str},
    {ngx_string("libinj:"), ngx_http_waf_parse_rule_libinj},
    {ngx_string("z:"),      ngx_http_waf_parse_rule_zone},
    {ngx_string("wl:"),     ngx_http_waf_parse_rule_whitelist},
    {ngx_string("note:"),   ngx_http_waf_parse_rule_note},

    {ngx_null_string, NULL}
};


static ngx_command_t  ngx_http_waf_commands[] = {

    { ngx_string("security_rule"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_waf_main_rule,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("security_loc_rule"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
      ngx_http_waf_loc_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("security_check"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_check_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      &ngx_http_waf_rule_actions },

    { ngx_string("security_waf"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, security_waf),
      NULL },

    { ngx_string("security_log"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
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


//-- init -------------------
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

    wlcf->security_waf = NGX_CONF_UNSET;
    wlcf->log_file = NULL;

    return wlcf;
}

// -- public ---------------
static u_char *ngx_strpbrk(u_char *b, u_char *e, char *s) {
    u_char *p = b;

    while (p < e) {
        if (ngx_strchr(s, *p) != NULL) {
            return p;
        }

        p++;
    }

    return NULL;
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
    hash.max_size = 1024;
    hash.bucket_size = ngx_align(512, ngx_cacheline_size);
    hash.name = "waf_vars_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, vars.elts, vars.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
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


// -- debug -----------------
#if (NGX_DEBUG)

static void
ngx_http_waf_print_public_rule(ngx_http_waf_public_rule_t *br)
{
    ngx_uint_t             x;
    ngx_http_waf_score_t  *scs, *sc;

    fprintf(stderr, "  public_rule: id:%ld str:%*s regex:%p handler: %p\n",
        br->id, (int)br->str.len, br->str.data, br->regex, br->handler);

    if (br->scores == NULL) return;

    fprintf(stderr, "    scores:%p\n", br->scores);
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
    ngx_uint_t            x;
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

#endif


// -- parse -----
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

    // merge rule
    if (prev != NULL) {
        prev_rules = prev->elts;
        for (i = 0; i < prev->nelts; i++) {
            rule = ngx_array_push(*conf);
            if (rule == NULL) {
                return NGX_ERROR;
            }

            ngx_memzero(rule, sizeof(ngx_http_waf_rule_t));

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
                ngx_http_waf_rule_set_wl_invalid(rule->sts);
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
                                continue;
                            }

                            if (ngx_http_waf_wl_mz(&zones[k],
                                rule->m_zone))
                            {
                                ngx_http_waf_wl_copy_mz(rule->sts,
                                    zones[k].flag);
                                continue;
                            }

                            if (ngx_http_waf_mz_ge(&zones[k], rule->m_zone)) {
                                ngx_http_waf_rule_set_wl_invalid(rule->sts);
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
            ngx_http_waf_sts_act_set_block(rule->sts);
            continue;
        }

        if (checks == NULL || checks->nelts == 0) {
            ngx_http_waf_rule_set_sc_invalid(rule->sts);
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
            ngx_http_waf_rule_set_sc_invalid(rule->sts);
        }

    }

    return NGX_OK;
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
    if (1 != conf->security_waf) {
        conf->security_waf = 0;
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

#if (NGX_DEBUG)
    ngx_http_waf_print_check_array(conf->check_rules, "conf->check_rules");
    ngx_http_waf_print_wl_array(conf->whitelists, "conf->whitelists");

    ngx_http_waf_print_rule_array(conf->url, "@conf->url");
#endif

    pr_array = wmcf->url;
    if (prev->url != NULL) {
        pr_array = prev->url;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->url) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->url, "conf->url");


    ngx_http_waf_print_rule_array(conf->url_var, "@conf->url_var");
#endif
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
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->url_var, "conf->url_var");


    ngx_http_waf_print_rule_array(conf->args, "@conf->args");
#endif
    pr_array = wmcf->args;
    if (prev->args != NULL) {
        pr_array = prev->args;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->args) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->args, "conf->args");


    ngx_http_waf_print_rule_array(conf->args_var, "@conf->args_var");
#endif
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
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->args_var, "conf->args_var");


    ngx_http_waf_print_rule_array(conf->headers, "@conf->headers");
#endif

    pr_array = wmcf->headers;
    if (prev->headers != NULL) {
        pr_array = prev->headers;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->headers) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->headers, "conf->headers");

    ngx_http_waf_print_rule_array(conf->headers_var, "@conf->headers_var");
#endif
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
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->headers_var, "conf->headers_var");


    ngx_http_waf_print_rule_array(conf->body, "@conf->body");
#endif
    pr_array = wmcf->body;
    if (prev->body != NULL) {
        pr_array = prev->body;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->body) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->body, "conf->body");

    ngx_http_waf_print_rule_array(conf->raw_body, "@conf->raw_body");
#endif
    pr_array = wmcf->raw_body;
    if (prev->raw_body != NULL) {
        pr_array = prev->raw_body;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->raw_body) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->raw_body, "conf->raw_body");

    ngx_http_waf_print_rule_array(conf->body_var, "@conf->body_var");
#endif
    pr_array = wmcf->body_var;
    if (prev->body_var != NULL) {
        pr_array = prev->body_var;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->body_var) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_vars_in_hash(cf, conf->body_var,
        &conf->body_var_hash) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->body_var, "conf->body_var");

    ngx_http_waf_print_rule_array(conf->body_file, "@conf->body_file");
#endif
    pr_array = wmcf->body_file;
    if (prev->body_file != NULL) {
        pr_array = prev->body_file;
    }

    if (ngx_http_waf_merge_rule_array(cf, conf->whitelists, conf->check_rules,
        pr_array, &conf->body_file) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#if (NGX_DEBUG)
    ngx_http_waf_print_rule_array(conf->body_file, "conf->body_file");
#endif


    if (conf->log_file != NULL || conf->log_off) {
        return NGX_CONF_OK;
    }

    conf->log_file = prev->log_file;
    conf->log_off  = prev->log_off;

    if (conf->log_file == NULL) {
        conf->log_off = 1;
    }

    return NGX_CONF_OK;
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

    ngx_memzero(r, sizeof(ngx_http_waf_rule_t));

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


static ngx_int_t
ngx_http_waf_add_whitelist(ngx_conf_t *cf, ngx_http_waf_rule_opt_t *opt,
    ngx_array_t **a)
{
    ngx_int_t                   *id, rc;
    ngx_flag_t                   vailid;
    ngx_uint_t                   i, j, k;
    ngx_http_waf_whitelist_t    *wl;
    ngx_http_waf_zone_t         *zones;
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

        ngx_memzero(wl, sizeof(ngx_http_waf_whitelist_t));

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
    ngx_http_waf_zone_t             *zone;

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
    ngx_http_variable_t             *var;
    ngx_conf_bitmask_t              *m;
    ngx_str_t                       *value, v;
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

    ngx_memzero(check, sizeof(ngx_http_waf_check_t));

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

    v = value[2];
    if (v.data[0] == '$') {
        ngx_http_waf_act_set_var_block(check->action_flag);
        v.data += 1;
        v.len -= 1;
        var = ngx_http_add_variable(cf, &v,
            NGX_HTTP_VAR_CHANGEABLE
            |NGX_HTTP_VAR_NOCACHEABLE
            |NGX_HTTP_VAR_NOHASH);

        var->get_handler = ngx_http_waf_check_variable;

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid arguments \"%V\"", &value[2]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_waf_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t    *wlcf = conf;

    ngx_str_t                  *value;

    value = cf->args->elts;

    if (wlcf->log_file != NULL) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        wlcf->log_off = 1;
        return NGX_CONF_OK;
    }

    wlcf->log_file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (wlcf->log_file == NULL) {
        return NGX_CONF_ERROR;
    }
    wlcf->log_off = 0;


    return NGX_CONF_OK;
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
    u_char               *p, *e, errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t   rc;


    p = str->data + parser->prefix.len;
    e = str->data + str->len;

    // TODO: lt@ le@ gt@ ge@ 
    // ct@xyz ne@xyz eq@xyz sw@xyz ew@xyz rx@xyz...
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

    if (p[0] == 'l' && p[1] == 'e') {
        p += 3;
        ngx_strlow(opt->p_rule->str.data, p, opt->p_rule->str.len);
        opt->p_rule->handler = ngx_http_waf_rule_str_le_handler;
    } else if (p[0] == 'g' && p[1] == 'e') {
        p += 3;
        ngx_strlow(opt->p_rule->str.data, p, opt->p_rule->str.len);
        opt->p_rule->handler = ngx_http_waf_rule_str_ge_handler;
    } else if (p[0] == 'c' && p[1] == 't') {
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

        sc->log_ctx = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_note(ngx_conf_t *cf, ngx_str_t *str,
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
    ngx_http_waf_zone_t          *zone;

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

        ngx_memzero(zone, sizeof(ngx_http_waf_zone_t));

        zone->flag = flag;

        if (ngx_http_waf_mz_is_general(flag)) {
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

        if (ngx_http_waf_mz_is_regex(flag)) {
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


// libinj:sql
// libinj:xss
static ngx_int_t
ngx_http_waf_parse_rule_libinj(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    u_char             *p;

    static ngx_str_t    sql = ngx_string("sql");
    static ngx_str_t    xss = ngx_string("xss");

    if (str->len - parser->prefix.len != 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid libinj in arguments \"%V\"", str);
        return NGX_ERROR;
    }

    p = str->data + parser->prefix.len;

    if (ngx_strncmp(p, sql.data, sql.len) == 0) {
        opt->p_rule->str = sql;
        opt->p_rule->handler = ngx_http_waf_rule_str_sqli_handler;

    } else if (ngx_strncmp(p, xss.data, xss.len) == 0) {
        opt->p_rule->str = xss;
        opt->p_rule->handler = ngx_http_waf_rule_str_xss_handler;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid libinj args in arguments \"%V\"", str);
        return NGX_ERROR;
    }

    return NGX_OK;
}


// -- rquest deal -------

static void
ngx_http_waf_score_calc(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_rule_t *rule, ngx_str_t str)
{
    ngx_uint_t                 k, idx;
    ngx_http_waf_score_t      *ss;
    ngx_http_waf_check_t      *cs;
    ngx_http_waf_log_ctx_t    *log;
    ngx_http_waf_loc_conf_t   *wlcf;


    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx http waf score calc rule id: %i addr:%p",
        rule->p_rule->id, rule->p_rule->scores);

    ngx_http_waf_ctx_copy_act(ctx->status, rule->sts);

    if (ngx_http_waf_sts_has_block(ctx->status)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx http waf score calc ctx block return ...");

        if (rule->p_rule->scores != NULL) {
            return;
        }

        ctx->logc = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_log_ctx_t));
        if (ctx->logc != NULL) {
            ctx->logc->rule = rule;
            ctx->logc->str = str;
        }

        return;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

#if (NGX_DEBUG)
    assert((ctx->scores != NULL));
#endif

    ss = ctx->scores->elts;
    cs = rule->score_checks->elts;
    for (k = 0; k < rule->score_checks->nelts; k++) {
        idx = cs[k].idx;
        ss[idx].score += cs[k].score;

        // TODO: optimize >=
        if (ss[idx].score > cs[k].threshold) {
            ctx->status |= cs[k].action_flag;
        }

        if (str.len > 128) {
            str.len = 128;
        }
        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http waf module score calc. id:%i tag:$%V score:%i total_score:%i"
            " str:%V",
            rule->p_rule->id, &cs[k].tag, cs[k].score, ss[idx].score, &str);


        if (wlcf->log_off) {
            continue;
        }

        if (ss[idx].log_ctx == NULL) {
            ss[idx].log_ctx = ngx_array_create(r->pool, 3,
                sizeof(ngx_http_waf_log_ctx_t));

            if (ss[idx].log_ctx == NULL) {
                continue;
            }
        }

        log = ngx_array_push(ss[idx].log_ctx);
        if (log == NULL) {
            continue;
        }

        log->score = cs[k].score;
        log->rule = rule;
        log->str  = str;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http waf module rule %d log", rule->p_rule->id);
    }
}


static ngx_int_t
ngx_http_waf_rule_str_ge_handler(ngx_http_waf_public_rule_t *pr,
    ngx_str_t *s)
{
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_waf_rule_str_le_handler(ngx_http_waf_public_rule_t *pr,
    ngx_str_t *s)
{
    return NGX_ERROR;
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

    if (s == NULL || s->data == NULL || s->len == 0) {
        return NGX_ERROR;
    }

    n = ngx_regex_exec(pr->regex, s, NULL, 0);
    if (n == NGX_REGEX_NO_MATCHED) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_rule_str_sqli_handler(ngx_http_waf_public_rule_t *pr,
    ngx_str_t *s)
{
    ngx_int_t                       issqli;
    struct libinjection_sqli_state  state;

    if (s == NULL || s->data == NULL || s->len == 0) {
        return NGX_ERROR;
    }

    libinjection_sqli_init(&state, (const char *)s->data, s->len, FLAG_NONE);
    issqli = libinjection_is_sqli(&state);
    if (!issqli) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_rule_str_xss_handler(ngx_http_waf_public_rule_t *pr,
    ngx_str_t *s)
{
    ngx_int_t       isxss;

    if (s == NULL || s->data == NULL || s->len == 0) {
        return NGX_ERROR;
    }

    isxss = libinjection_xss((const char *)s->data, s->len);
    if (!isxss) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_waf_rule_str_match(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_rule_t *rule, ngx_str_t *key, ngx_str_t *val)
{

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx http waf rule str match handler");

    // match key
    if (key != NULL && key->len > 0
        && ngx_http_waf_mz_key(rule->m_zone->flag)
        && !ngx_http_waf_rule_wl_mz_key(rule->sts))
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx http waf rule str match key:%V", key);

        if (rule->p_rule->handler(rule->p_rule, key) == NGX_OK) {
            ngx_http_waf_score_calc(r, ctx, rule, *key);
        }
    }

    // match value
    if (val != NULL && val->len > 0
        && ngx_http_waf_mz_val(rule->m_zone->flag)
        && !ngx_http_waf_rule_wl_mz_val(rule->sts))
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx http waf rule str match val:%V", val);

        if (rule->p_rule->handler(rule->p_rule, val) == NGX_OK) {
            ngx_http_waf_score_calc(r, ctx, rule, *val);
        }
    }


    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx http waf rule str match handler done");

    return;
}


static void
ngx_http_waf_hash_find(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
    ngx_hash_t *hash, ngx_str_t *key, ngx_str_t *val, ngx_uint_t hk)
{
    ngx_uint_t                    i, k;
    ngx_hash_elt_t               *elt;
    ngx_http_waf_rule_t          *rule;
    ngx_http_waf_zone_t          *mzs;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx http waf hash find handler");

    if (hash == NULL || key == NULL || hash->size == 0 || key->len == 0) {
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
            if (ngx_tolower(key->data[i]) != elt->name[i]) {
                goto next;
            }
        }

        rule = elt->value;
        if (ngx_http_waf_rule_invalid(rule->sts)) {
            goto next;
        }

        if (rule->wl_zones != NULL) {
            mzs = rule->wl_zones->elts;
            for (k = 0; k < rule->wl_zones->nelts; k++) {
                if (ngx_http_waf_mz_is_regex(mzs[k].flag)) {
                    if (ngx_http_waf_zone_regex_exec(&mzs[k], key) == NGX_OK) {
                        goto next;
                    }
                } else {
                    if (key->len == mzs[k].name.len && ngx_strncasecmp(key->data,
                        mzs[k].name.data, key->len) == 0)
                    {
                        goto next;
                    }
                }
            }
        }


        ngx_http_waf_rule_str_match(r, ctx, rule, key, val);

    next:

        elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                                               sizeof(void *));
        continue;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx http waf hash find done");
    return;
}


static ngx_int_t
ngx_http_waf_rule_filter(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
  ngx_hash_t *hash, ngx_array_t *rule,
  ngx_str_t *key, ngx_str_t *val, ngx_uint_t key_hash)
{
    ngx_uint_t              j, k;
    ngx_http_waf_rule_t    *rs;
    ngx_http_waf_zone_t    *mzs;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx http waf rule filter handler");

    ngx_http_waf_hash_find(r, ctx, hash, key, val, key_hash);

    if (rule == NULL) {
        goto done;
    }

    rs = rule->elts;
    for (j = 0; j < rule->nelts; j++) {
        if (ngx_http_waf_rule_invalid(rs[j].sts)) {
            goto nxt_rule;
        }

        // wl_zones ngx_http_waf_zone_t
        if (rs[j].wl_zones != NULL) {
            mzs = rs[j].wl_zones->elts;
            for (k = 0; k < rs[j].wl_zones->nelts; k++) {
                if (ngx_http_waf_mz_is_regex(mzs[k].flag)) {
                    if (ngx_http_waf_zone_regex_exec(&mzs[k], key) == NGX_OK) {
                        goto nxt_rule;
                    }
                } else {
                    if (key->len == mzs[k].name.len && ngx_strncasecmp(key->data,
                        mzs[k].name.data, key->len) == 0)
                    {
                        goto nxt_rule;
                    }
                }
            }
        }

        if(ngx_http_waf_mz_is_general(rs[j].m_zone->flag)) {

            ngx_http_waf_rule_str_match(r, ctx, &rs[j], key, val);
        } else if (ngx_http_waf_mz_is_regex(rs[j].m_zone->flag)) {

            if (ngx_http_waf_zone_regex_exec(rs[j].m_zone, key) == NGX_OK) {

                ngx_http_waf_rule_str_match(r, ctx, &rs[j], key, val);
            }
        }
#if (NGX_DEBUG)
        else {
            // impossible doing here.
            assert(0);
        }
#endif

    nxt_rule:

        if (ngx_http_waf_score_is_done(ctx->status)) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx http waf rule filter handler block");
            return NGX_ABORT;
        }

        continue;
    }

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx http waf rule filter handler done");

    return NGX_OK;
}


static void
ngx_http_waf_score_url(ngx_http_request_t *r, ngx_http_waf_loc_conf_t *wlcf)
{
    ngx_http_waf_ctx_t           *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score url: %V", &r->uri);

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL || ngx_http_waf_score_is_done(ctx->status)) {
        return;
    }

    ngx_http_waf_rule_filter(r, ctx, &wlcf->url_var_hash, wlcf->url,
        &r->uri, &r->uri, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score url: %V done", &r->uri);
    return;
}


static void
ngx_http_waf_score_args(ngx_http_request_t *r, ngx_http_waf_loc_conf_t *wlcf)
{
    u_char                       *p, *q, *e;
    ngx_str_t                     key, val;
    ngx_http_waf_ctx_t           *ctx;

    enum {
        sw_key = 0,
        sw_val
    } state;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score args: %V", &r->args);

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL || ngx_http_waf_score_is_done(ctx->status)) {
        return;
    }

#if 1
    u_char *dst, *src;
    src = r->args.data;

    dst = ngx_pnalloc(r->pool, r->args.len);
    if (dst == NULL) {
        return;
    }
    p = e = dst;

    ngx_unescape_uri(&e, &src, r->args.len, 0);
#else
    p = r->args.data;
    e = r->args.data + r->args.len;
#endif

    key.len = 0;
    val.len = 0;

    q = p;
    state = sw_key;

    while(p < e) {
        if (*p == '=' && state == sw_key) {
            key.data = q;
            key.len  = p - q;

            p++;
            q = p;

            state = sw_val;
        } else if ( ((*(p+1) == '&' || p+1 == e) && state == sw_val)
            || ((p+1 == e) && state == sw_key) ) {

            val.data = q;
            val.len  = p - q + 1;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http waf module score args key:%V val:%V", &key, &val);

            ngx_http_waf_rule_filter(r, ctx, &wlcf->args_var_hash, wlcf->args,
                &key, &val, 0);

            p += 2;
            q = p;
            state = sw_key;

            key.len = 0;
            key.data = NULL;
            val.len = 0;
            val.data = NULL;

        } else {
            p++;
        }

        if (ngx_http_waf_score_is_done(ctx->status)) {
            goto done;
        }
    }


done:
#if 1
    ngx_pfree(r->pool, dst);
#endif


    return;
}


static void
ngx_http_waf_score_headers(ngx_http_request_t *r, ngx_http_waf_loc_conf_t *wlcf)
{
    ngx_uint_t                    i;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_waf_ctx_t           *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score headers ...");

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL || ngx_http_waf_score_is_done(ctx->status)) {
        return;
    }

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

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http waf module score headers key:%V val:%V",
            &header[i].key, &header[i].value);

        ngx_http_waf_rule_filter(r, ctx, &wlcf->headers_var_hash, wlcf->headers,
            &header[i].key, &header[i].value, header[i].hash);

        if (ngx_http_waf_score_is_done(ctx->status)) {
            goto done;
        }
    }

done:
    return;
}



static void
ngx_http_waf_score_body(ngx_http_request_t *r, ngx_http_waf_loc_conf_t *wlcf)
{
    u_char                       *p, *q, *e, *t;
    ngx_str_t                     body, *type, key, val, content, boundary;
    ngx_int_t                     is_file, over;
    ngx_chain_t                  *cl;
    ngx_http_waf_ctx_t           *ctx;

    ngx_str_t    ct_urlencode = ngx_string("application/x-www-form-urlencoded");
    ngx_str_t    ct_multipart = ngx_string("multipart/form-data");
    ngx_str_t    boundary_prefix = ngx_string("boundary");
    ngx_str_t    ct_disposition = ngx_string("Content-Disposition");

    enum {
        sw_key = 0,
        sw_val
    } state;

    state = sw_key;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL || ngx_http_waf_score_is_done(ctx->status)) {
        return;
    }

    if (r->request_body == NULL
        || r->request_body->temp_file
        || r->request_body->bufs == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "ngx http waf module score body, body is null!");
        return;
    }

    type = &r->headers_in.content_type->value;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "ngx http waf module socore body content type:%V", type);

    cl = r->request_body->bufs;
    if (cl->next == NULL) {
        body.data = cl->buf->pos;
        body.len  = cl->buf->last - cl->buf->pos;

    } else {
        body.len = 0;

        for (; cl; cl = cl->next) {
            body.len += cl->buf->last - cl->buf->pos;
        }

        if (body.len > 0) {
            body.data = ngx_pcalloc(r->pool, body.len + 1);
            if (body.data != NULL) {
                p = body.data;
                for (cl = r->request_body->bufs; cl; cl = cl->next) {
                    p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
                }
            }
        }
    }

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "ngx http waf module socre body file length: %d content:\n"
                    "%V", body.len, &body);
#endif

    // raw_body
    ngx_http_waf_rule_filter(r, ctx, NULL, wlcf->raw_body, NULL, &body, 0);


    // TODO: return

    // parse body
    if (ct_urlencode.len <= type->len
        && ngx_strncasecmp(type->data, ct_urlencode.data,
          ct_urlencode.len) == 0)
    {
        p = body.data;
        e = body.data + body.len;
        q = p;

        while(p < e) {
            if (*p == '=' && state == sw_key) {
                key.data = q;
                key.len  = p - q;

                p++;
                q = p;

                state = sw_val;
            } else if ( ((*(p+1) == '&' || p+1 == e) && state == sw_val)
                || ((p+1 == e) && state == sw_key) ) {

                val.data = q;
                val.len  = p - q + 1;

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score body urlencode key:%V val:%V", 
                    &key, &val);

                ngx_http_waf_rule_filter(r, ctx, &wlcf->body_var_hash,
                    wlcf->body, &key, &val, 0);

                p += 2;
                q = p;
                state = sw_key;

                key.len = 0;
                key.data = NULL;
                val.len = 0;
                val.data = NULL;

            } else {
                p++;
            }

            if (ngx_http_waf_score_is_done(ctx->status)) {
                goto done;
            }
        }

    } else if (ct_multipart.len <= type->len && ngx_strncasecmp(
          type->data, ct_multipart.data,
          ct_multipart.len) == 0)
    {
        // https://www.ietf.org/rfc/rfc1867.txt
        ngx_str_null(&boundary);

        t = ngx_strnstr(type->data + ct_multipart.len,
              (char *)boundary_prefix.data,
              type->len - ct_multipart.len);
        if (t == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http waf module multipart content type error, type:%V", type);
            goto done;
        }

        p = t + boundary_prefix.len;
        e  = type->data + type->len;
        while (*p == ' ' || *p == '=' || *p == '\'' || *p == '"') {
            p++;
        }

        while (*e == ' ' || *e == '\'' || *e == '"') {
            e--;
        }

        boundary.data = ngx_pcalloc(r->pool, 2 + e - p + 1);
        if (boundary.data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http waf module parse multipart boundary error");
            goto done;
        }

        boundary.data[0] = '-';
        boundary.data[1] = '-';
        ngx_memcpy(boundary.data + 2, p, e - p);
        boundary.len = 2 + e - p;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http waf module score body boundary:%V", &boundary);

        p = body.data;
        q = p;
        e = body.data + body.len;

        p = ngx_strnstr(p, (char *)boundary.data, e - p);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http waf module parse multipart body boundary start error");
            goto done;
        }
        p += boundary.len;

        while (p < e) {
            over = 1;
            is_file = 0;
            ngx_str_null(&key);
            ngx_str_null(&val);
            ngx_str_null(&content);

            // maybe
            while (*p != CR && *p != LF && p < e) p++;

            if (p[0] != CR || p[1] != LF) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http waf multipart body boundary crlf error");
                goto done;
            }
            p += 2;

            // maybe
            while(*p == ' ' && p < e) p++;

            if (ngx_strncasecmp(p, ct_disposition.data,
                ct_disposition.len) == 0)
            {
                p += ct_disposition.len;
                // maybe
                while((*p == ':' || *p == ' ') && p < e) p++;

                if (e - p > 9 && 0 ==
                    ngx_strncasecmp(p, (u_char *)"form-data", 9))
                {
                    p += 9;
                }
            }

            while (p < e) {
                // is not filename=
                if (*(p-1) != 'e' && *(p-1) != 'E'
                    && ngx_strncasecmp(p, (u_char *)"name=", 5) == 0)
                {
                    p += 5;  // sizeof(name=)-1

                    // maybe
                    while(*p == ' ' || *p == '"' || *p == '\'') p++;
                    q = p;

                    p = ngx_strpbrk(p, e, "\"'; \r");
                    if (p == NULL) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "http waf multipart body name end error");
                        goto done;
                    }

                    key.data = q;
                    key.len = p - q;

                    // maybe
                    while (p < e && (*p == ' ' || *p == '"'
                            || *p == '\'' || *p == ';'))
                    {
                        p++;
                    }
                }

                if (over && ngx_strncasecmp(p, (u_char *)"filename=", 9) == 0) {
                    p += 9;    // sizeof("filename=")-1
                    // maybe
                    while (*p == '"' || *p == '\'' || *p == ' ') p++;
                    q = p;
                    p = ngx_strpbrk(p, e, "\"'; \r");
                    if (p == NULL) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "http waf multipart body filename error");
                        goto done;
                    }

                    val.data = q;
                    val.len  = p - q;
                    while (*p == '"' || *p == '\'' || *p == ' ') p++;
                    q = p;

                    over = 0;
                    is_file = 1;

                    if (*p == ';') {
                        over = 1;
                        p++;
                    }

                    if (e - p > 15 && ngx_strncasecmp(p,
                            (u_char *) CRLF "Content-Type:", 15) == 0)
                    {
                        p += 15;
                        while (*p == ' ' && p < e) p++;
                        // application/octet-stream
                    }
                }

                if (key.len > 0 && val.len > 0) {
                    // check
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "http waf module score body multipart "
                        "name:[%V] filename:[%V]",
                        &key, &val);

                    ngx_http_waf_rule_filter(r, ctx, &wlcf->body_var_hash,
                        wlcf->body, &key, &val, 0);

                    val.len = 0;
                    over = 1;
                }

                if (p[0] == CR && p[1] == LF && p[2] == CR && p[3] == LF) {
                    p += 4;
                    q = p;
                    break;
                }

                p++;
            }

            p = ngx_strnstr(p, CRLF "--", e - p);
            if (p == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "http waf multipart body name's value error");
                goto done;
            }

            if (is_file == 1) {
                content.data = q;
                content.len  = p - q;

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "http waf module score body multipart file: [%V]", &content);

                ngx_http_waf_rule_filter(r, ctx, NULL, wlcf->body_file,
                    NULL, &content, 0);

                is_file = 0;

            } else {

                val.data = q;
                val.len  = p - q;

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module score body multipart "
                    "name:[%V] val:[%V]",
                    &key, &val);

                ngx_http_waf_rule_filter(r, ctx, &wlcf->body_var_hash,
                    wlcf->body, &key, &val, 0);
            }
            p += 2;  // sizeof(CRLF) - 1

            key.len     = 0;
            val.len     = 0;
            content.len = 0;

            if (ngx_strnstr(p, (char *)boundary.data, e - p) == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "http waf multipart body boundary end error");
                goto done;
            }
            p += boundary.len;

            if (p + 2 == e && p[0] == '-' && p[1] == '-') {
                goto done;
            }
        }
    }

done:
    if (boundary.data != NULL) {
        ngx_pfree(r->pool, boundary.data);
        boundary.data = NULL;
    }

    return;
}


void ngx_http_waf_body_handler(ngx_http_request_t *r)
{
    ngx_http_waf_ctx_t  *ctx;

    r->main->count--;
    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (!ctx->wait_body) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf body handler body have ready!");
        return;
    }

    ctx->wait_body = 0;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf body handler read body done!");

    if (ctx->interrupt) {
        ctx->interrupt = 0;
        ngx_http_core_run_phases(r);
    }

    return;
}


static ngx_int_t
ngx_http_waf_check_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    if (ctx == NULL || !ngx_http_waf_sts_has_block(ctx->status)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf check variable null");
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = (u_char *) "block";
    v->len = sizeof("block") - 1;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf check variable block");

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_check(ngx_http_waf_ctx_t *ctx)
{
    if (ngx_http_waf_sts_has_block(ctx->status) 
      && !ngx_http_waf_sts_has_var(ctx->status)) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (ngx_http_waf_sts_has_drop(ctx->status)) {
        return NGX_HTTP_CLOSE;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_waf_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_http_waf_ctx_t         *ctx;
    ngx_http_waf_check_t       *checks;
    ngx_http_waf_score_t       *sc;
    ngx_http_waf_loc_conf_t    *wlcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module handler");

    if (r->internal) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module internal return");
        return NGX_DECLINED;
    }

    if (r != r->main) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module subrequest return");
        return NGX_DECLINED;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (wlcf == NULL || !wlcf->security_waf) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf module invalid");

        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ctx->wait_body  = 1;
        ctx->check_done = 0;
        ctx->interrupt  = 0;

        if (wlcf->check_rules != NULL && wlcf->check_rules->nelts > 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf handler create ctx->scores");
            ctx->scores = ngx_array_create(r->pool, wlcf->check_rules->nelts,
                sizeof(ngx_http_waf_score_t));
            if (ctx->scores == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http waf handler create ctx->scores error");
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
                sc->log_ctx = NULL;
            }
        }

        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;
    rc = ngx_http_read_client_request_body(r, ngx_http_waf_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (rc == NGX_AGAIN || ctx->wait_body) {
        ctx->interrupt = 1;
        return NGX_DONE;
    }

    if (!ctx->check_done) {
        ngx_http_waf_score_url(r, wlcf);
        ngx_http_waf_score_args(r, wlcf);
        ngx_http_waf_score_headers(r, wlcf);
        ngx_http_waf_score_body(r, wlcf);
        ctx->check_done = 1;
    }

    return ngx_http_waf_check(ctx);
}



static ngx_int_t
ngx_http_waf_log_handler(ngx_http_request_t *r)
{
    u_char                      line[4096], *p, *buf;
    size_t                      len;
    ngx_uint_t                  i, j;
    ngx_http_waf_ctx_t         *ctx;
    ngx_http_waf_score_t       *scs;
    ngx_http_waf_log_ctx_t     *logc, *lc;
    ngx_http_waf_loc_conf_t    *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (wlcf->log_off) {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL || ctx->status == 0) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx waf log handler");

    len = 4096;
    ngx_memzero(line, 4096);
    buf = line;

    p = ngx_snprintf(buf, len, "{\"timestamp\": \"%T\", \"remote_ip\": \"%V\", "
        "\"host\": \"%V\", \"method\": \"%V\", \"uri\": \"%V\", "
        "\"result\": \"%s\", ",
        ngx_time(), &r->connection->addr_text, &r->headers_in.host->value,
        &r->method_name, &r->unparsed_uri,
        ngx_http_waf_sts_has_block(ctx->status)? "BLOCK": "LOG");

    len -= p - buf;
    buf = p;

    if (ctx->scores != NULL) {
        scs = ctx->scores->elts;
        for (i = 0; i < ctx->scores->nelts && len > 0; i++) {
            p = ngx_snprintf(buf, len, "\"%V_total\": \"%ui\", ",
                &scs[i].tag, scs[i].score);

            len -= p - buf;
            buf = p;

            if (scs[i].log_ctx == NULL || scs[i].log_ctx->nelts == 0) {
                continue;
            }

            logc = scs[i].log_ctx->elts;
            for (j = 0; j < scs[i].log_ctx->nelts && len > 0; j++) {
                lc = &logc[j];

                p = ngx_snprintf(buf, len, "\"rule_%V_%d_score\": \"%ui\", "
                    "\"rule_%V_%d_zflag\": \"0x%Xd\", "
                    "\"rule_%V_%d_zname\": \"%V\", "
                    "\"rule_%V_%d_str\": \"%V\", "
                    "\"match_%V_%d_val\": \"%V\", ",
                    &scs[i].tag, lc->rule->p_rule->id, lc->score,
                    &scs[i].tag, lc->rule->p_rule->id, lc->rule->m_zone->flag,
                    &scs[i].tag, lc->rule->p_rule->id, &lc->rule->m_zone->name,
                    &scs[i].tag, lc->rule->p_rule->id, &lc->rule->p_rule->str,
                    &scs[i].tag, lc->rule->p_rule->id, &lc->str);

                len -= p - buf;
                buf = p;
            }
        }
    }

    if (ctx->logc != NULL) {
        p = ngx_snprintf(buf, len, "\"rule_BLOCK_%d_score\": \"0\", "
            "\"rule_BLOCK_%d_zflag\": \"0x%Xd\", "
            "\"rule_BLOCK_%d_zname\": \"%V\", "
            "\"rule_BLOCK_%d_str\": \"%V\", "
            "\"match_BLOCK_%d_val\": \"%V\", ",
            ctx->logc->rule->p_rule->id,
            ctx->logc->rule->p_rule->id, ctx->logc->rule->m_zone->flag,
            ctx->logc->rule->p_rule->id, &ctx->logc->rule->m_zone->name,
            ctx->logc->rule->p_rule->id, &ctx->logc->rule->p_rule->str,
            ctx->logc->rule->p_rule->id, &ctx->logc->str
            );

            len -= p - buf;
            buf = p;
    }

    // buf - 2 for cover ", "
    p = ngx_snprintf(buf - 2, len + 2, "}\n");

    ngx_write_fd(wlcf->log_file->fd, line, p-line);

    return NGX_OK;
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


    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_waf_log_handler;

    return NGX_OK;
}