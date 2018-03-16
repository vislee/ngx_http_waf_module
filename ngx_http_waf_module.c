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


typedef struct ngx_http_waf_basic_rule_s {
    ngx_uint_t            id;
    ngx_str_t             str;
    ngx_regex_t          *regex;
    ngx_array_t          *scores;       /* ngx_http_waf_score_t. maybe null */
    ngx_uint_t            action_flag;  /* usual handler. maybe 0 */
    unsigned              rx:1;
} ngx_http_waf_basic_rule_t;


typedef struct ngx_http_waf_customer_zone_s {
    ngx_uint_t    zone_flag;
    ngx_str_t     name;
    ngx_regex_t  *regex;
} ngx_http_waf_customer_zone_t;


typedef struct ngx_http_waf_rule_opt_s {
    // union {
    //     ngx_http_waf_basic_rule_t    *b_rule;
    //     ngx_array_t                  *whitelists; /* ngx_int_t */
    // } u;
    ngx_http_waf_basic_rule_t    *b_rule;
    ngx_array_t                  *whitelists; /* ngx_int_t */
    // ngx_http_waf_customer_zone_t
    ngx_array_t                  *c_zones;
} ngx_http_waf_rule_opt_t;


typedef struct ngx_http_waf_rule_s {
    ngx_http_waf_customer_zone_t *c_zone;
    ngx_http_waf_basic_rule_t    *b_rule;
    unsigned                      white:1;
} ngx_http_waf_rule_t;


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

    ngx_hash_t       headers_var_hash;
    ngx_hash_t       args_var_hash;
    ngx_hash_t       url_var_hash;
    ngx_hash_t       body_var_hash;

    ngx_array_t     *check_rule;  /* ngx_http_waf_check_t */
    ngx_flag_t       libinjection_sql;
    ngx_flag_t       libinjection_xss;
} ngx_http_waf_loc_conf_t;


typedef struct ngx_http_waf_add_rule_s {
    ngx_uint_t   flag;
    ngx_uint_t   offset;
    ngx_int_t  (*handler)(ngx_conf_t *cf, ngx_http_waf_basic_rule_t *b,
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


static char *ngx_http_waf_main_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_basic_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_conf_waf_check_rule(ngx_conf_t *cf, ngx_command_t *cmd,
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
static ngx_int_t  ngx_http_waf_add_rule(ngx_conf_t *cf,
    ngx_http_waf_basic_rule_t *b, ngx_http_waf_customer_zone_t *z,
    void *conf, ngx_int_t offset);

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



static ngx_http_waf_add_rule_t  ngx_http_waf_main_conf_rules[] = {

    { NGX_HTTP_WAF_MZ_G_URL,
      offsetof(ngx_http_waf_main_conf_t, url),
      ngx_http_waf_add_rule },

    { NGX_HTTP_WAF_MZ_G_ARGS,
      offsetof(ngx_http_waf_main_conf_t, args),
      ngx_http_waf_add_rule },

    { NGX_HTTP_WAF_MZ_G_HEADERS,
      offsetof(ngx_http_waf_main_conf_t, headers),
      ngx_http_waf_add_rule },

    { NGX_HTTP_WAF_MZ_G_BODY,
      offsetof(ngx_http_waf_main_conf_t, body),
      ngx_http_waf_add_rule },

    { NGX_HTTP_WAF_MZ_G_RAW_BODY,
      offsetof(ngx_http_waf_main_conf_t, raw_body),
      ngx_http_waf_add_rule },

    { NGX_HTTP_WAF_MZ_URL_VAR,
      offsetof(ngx_http_waf_main_conf_t, url_var),
      ngx_http_waf_add_rule },

    { NGX_HTTP_WAF_MZ_ARGS_VAR,
      offsetof(ngx_http_waf_main_conf_t, args_var),
      ngx_http_waf_add_rule },

    { NGX_HTTP_WAF_MZ_HEADERS_VAR,
      offsetof(ngx_http_waf_main_conf_t, headers_var),
      ngx_http_waf_add_rule },

    { NGX_HTTP_WAF_MZ_BODY_VAR,
      offsetof(ngx_http_waf_main_conf_t, body_var),
      ngx_http_waf_add_rule },

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
      ngx_conf_waf_check_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
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
    NULL,                                  /* postconfiguration */

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

    return wlcf;
}


static ngx_int_t
ngx_http_waf_parse_rule(ngx_conf_t *cf, ngx_http_waf_rule_opt_t *opt_rule)
{
    ngx_int_t                    res, vailid;
    ngx_str_t                   *value;
    ngx_uint_t                   i, j;
    ngx_http_waf_rule_parser_t  *parser;

    value = cf->args->elts;

    opt_rule->b_rule = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_basic_rule_t));
    if (opt_rule->b_rule == NULL) {
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
ngx_http_waf_add_rule(ngx_conf_t *cf, ngx_http_waf_basic_rule_t *b,
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
    r->b_rule = b;

    return NGX_OK;
}


static char *
ngx_http_waf_main_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                        i, j, rc, vailid;
    ngx_http_waf_main_conf_t        *wmcf = conf;
    ngx_http_waf_rule_opt_t          opt;
    ngx_http_waf_customer_zone_t    *zone;


    ngx_memzero(&opt, sizeof(ngx_http_waf_rule_opt_t));
    if (ngx_http_waf_parse_rule(cf, &opt) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (opt.c_zones == NULL || opt.c_zones.nelts == 0) {
        return "the rule lack of match zone";
    }

    zone = opt.c_zones.elts;
    for (i = 0; i < opt.c_zones.nelts; i++) {
        vailid = 0;
        for (j = 0; ngx_http_waf_main_conf_rules[j].flag != 0; j++) {
            if (ngx_http_waf_main_conf_rules[j].flag & zone[i].zone_flag
                == ngx_http_waf_main_conf_rules[j].flag) {

                rc = ngx_http_waf_main_conf_rules[j].handler(cf, opt.b_rule,
                &zone[i], wmcf,ngx_http_waf_main_conf_rules[j].offset);

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
    ngx_str_t                *value;
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    value = cf->args->elts;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_id(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{
    opt_rule->b_rule->id = ngx_atoi(str->data + parser->prefix.len,
        str->len - parser->prefix.len);

    if (opt_rule->b_rule->id == NGX_ERROR) {
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
    opt_rule->b_rule->str.len  = str->len - parser->prefix.len;
    opt_rule->b_rule->str.data = ngx_palloc(cf->pool, opt_rule->b_rule->str.len);
    if (opt_rule->b_rule->str.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(opt_rule->b_rule->str.data, str->data + parser->prefix.len,
        opt_rule->b_rule->str.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_parse_rule_rx(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt_rule)
{
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    opt_rule->b_rule->str.len  = str->len - parser->prefix.len;
    opt_rule->b_rule->str.data = str->data + parser->prefix.len;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc->pool = cf->pool;
    rc->err.len = NGX_MAX_CONF_ERRSTR;
    rc->err.data = errstr;

    rc->options = NGX_REGEX_CASELESS;
    rc->pattern = opt_rule->b_rule->str;

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
            s = ngx_strchr(p, ':');
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

                opt_rule->b_rule->action_flag |=
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

    if (opt_rule->whitelists == NULL) {
        opt_rule->whitelists = ngx_array_create(cf->pool, 3, sizeof(ngx_int_t));
        if (opt_rule->whitelists == NULL) {
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

        a = (ngx_int_t *)ngx_array_push(opt_rule->whitelists);
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







