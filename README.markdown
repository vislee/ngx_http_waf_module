Name
====

[![travis-ci](https://travis-ci.org/vislee/ngx_http_waf_module.svg?branch=master)](https://travis-ci.org/vislee/ngx_http_waf_module)
[![Coverage Status](https://coveralls.io/repos/github/vislee/ngx_http_waf_module/badge.svg?branch=master)](https://coveralls.io/github/vislee/ngx_http_waf_module?branch=master)

The **ngx_http_waf_module** is an open-source high-performance simple-rule easy-extend web application firewall(WAF) module for Nginx.


Table of Contents
=================
* [Name](#name)
* [Status](#status)
* [Install](#install)
* [Example Configuration](#example-configuration)
* [TODO](#todo)
* [Directives](#directives)
    * [security_rule](#security_rule)
    * [security_loc_rule](#security_loc_rule)
    * [security_waf](#security_waf)
    * [security_check](#security_check)
    * [security_log](#security_log)
* [New match strategy](#new-match-strategy)
* [Author](#author)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)


Status
======
The ngx_http_waf_module is currently in active development.


Install
=======

```sh
./configure --prefix=/usr/local/nginx --add-dynamic-module=github.com/vislee/ngx_http_waf_module --with-compat
```

[Back to TOC](#table-of-contents)

Example Configuration
====================

```nginx

load_module ./modules/ngx_http_waf_module.so;
events {
    ......
}

http {
   ......
    security_rule id:1001 "str:rx@^[a-z]{1,3}" "s:$BYPASS:1,$SQLI:2" z:V_HEADERS:bar|ARGS;
    security_rule id:1002 "str:!sw@/test.php" s:$XSS:3,$BYPASS:3 z:#URL;
    security_rule id:1003 "libinj:sql" "s:$SQLI:9" z:V_ARGS:foo;
    security_rule id:1004 "libinj:decode_url|xss" "s:$XSS:9" z:V_ARGS:foo "note:test rule by vislee";
    security_rule id:1005 "str:eq@testbody" "s:$BYPASS:2" "z:BODY";
    security_rule id:1006 "str:decode_base64|decode_url|ct@test file data" "s:$BYPASS:2" "z:V_BODY:input";
    security_rule id:1007 "str:ct@eval" "s:$HANG:2" "z:#FILE";
    security_rule id:1008 "str:ct@testphp" "s:$HANG:2" "z:X_FILE:^[a-z]{1,5}\.php$";
    security_rule id:1009 "str:ct@testphp" "s:$BYPASS:2" "z:#RAW_BODY";

    map $sec_result $ups {
        "block" block;
        default runtime;
    }

    server {
        location / {
            client_body_buffer_size 1m;

            security_waf on;
            security_log ./logs/waf.log;

            security_loc_rule wl:1003 z:V_ARGS:test;
            security_loc_rule id:90001 str:eq@vislee s:$BYPASS:4 z:V_HEADERS:name;

            security_check "$HANG>4" LOG;
            security_check "$BYPASS>8" $sec_result;
            security_check "$SQLI>8" DROP;
            security_check "$XSS>8" BLOCK;

            proxy_pass http://$ups;
        }
    }

```

[Back to TOC](#table-of-contents)

TODO
==========

+ add directive `security_timeout` limit rule filter timeout.

[Back to TOC](#table-of-contents)

Directives
==========

security_rule
-------------
**syntax:** *security_rule rule*

**default:** *no*

**context:** *http*

Set general rules. All the `location` contained in `http` is visible.

The rule format:

 `security_rule id:number match-strategy "s:$TAG:score,$TAG2:score" "z:zones" "note:message";`

+ id: The ID of the rule.
+ match-strategy: The strategy of rule.
  + str:[decode_func1|decode_func2|][!]le@string
  + str:[decode_func1|decode_func2|][!]ge@string
  + str:[decode_func1|decode_func2|][!]ct@string
  + str:[decode_func1|decode_func2|][!]eq@string
  + str:[decode_func1|decode_func2|][!]sw@string
  + str:[decode_func1|decode_func2|][!]ew@string
  + str:[decode_func1|decode_func2|][!]rx@regex
  + libinj:[decode_func1|decode_func2|]sql
  + libinj:[decode_func1|decode_func2|]xss
  + hash:[!]md5@hashcode
  + hash:[!]crc32@hashcode
  + hash:[!]crc32_long@hashcode
  + libmagic:[!]mime_type@mime_type

>>decode_func: decode_url or decode_base64

>>!: not. eg: "!eq@test" - Is not equal to 'test'. 

+ zones: The match zones of rule.
  + #URL
  + V_URL:string
  + X_URL:regex
  + [@ | #]ARGS
  + V_ARGS:string
  + X_ARGS:regex
  + [@ | #]HEADERS
  + V_HEADERS:string
  + X_HEADERS:regex
  + #RAW_BODY
  + [@ | #]BODY
  + V_BODY:string
  + X_BODY:regex
  + #FILE
  + X_FILE:regex

For example:

  "str:eq@/index.php" "z:#URL"  `curl 'http://x/index.php'` will be blocked

  "str:eq@bar" "z:V_ARGS:foo"  `curl 'http://x/?foo=bar'` will be blocked

  "str:eq@bar" "z:V_HEADERS:foo"  `curl -H'foo: bar' 'http://x/'` will be blocked


A complete rule configuration.

```nginx
security_rule id:100 "str:decode_base64|decode_url|!eq@foo bar" "s:$ATT:2,$SQLI:1" "z:V_ARGS:foo|#HEADERS" "note:test rule";
```


[Back to TOC](#table-of-contents)

security_loc_rule
-----------------
**syntax:** *security_loc_rule rule*

**default:** *no*

**context:** *location*

Set the location rules.

Also, you can set the whitelist disable of the general rules of the specified IDs.

The whitelist rule format:
```nginx
security_loc_rule "wl:id1,id2" "z:zones" "note:test whitelist";
```


[Back to TOC](#table-of-contents)

security_waf
------------
**syntax:** *security_waf <on|off>*

**default:** *off*

**context:** *location*

Enables or disables this module.

[Back to TOC](#table-of-contents)


security_check
--------------
**syntax:** *security_check $tag>threshold <LOG|BLOCK|DROP|ALLOW|$variable>*

**default:** *no*

**context:** *location*

Setting rules accumulating scoring thresholds and actions.

The action include:

  + LOG: only logged.
  + BLOCK: refuse the request, return 403.
  + DROP: close the connection, Is equivalent to return 444.
  + ALLOW: skip the rest of the rules.
  + $variable: return string "block" else return nil.

[Back to TOC](#table-of-contents)

security_log
------------
**syntax:** *security_log <file|off> [unflat]*

**default:** *off*

**context:** *location*

A log that requests a hit rule.

Logging to [syslog](http://nginx.org/en/docs/syslog.html) can be configured by specifying the “syslog:” prefix.

[Back to TOC](#table-of-contents)


New match strategy
===========

If you want to expand `match-strategy`. Only need to implement two function:
The function of parse directive and The matching-strategy callback function.

And then the parse directive function registered into the array of `ngx_http_waf_rule_parser_item`. 

For example, the `libinj:xss` and `libinj:sql` expand.

```c
// The parse directive function
static ngx_int_t
ngx_http_waf_parse_rule_libinj(ngx_conf_t *cf, ngx_str_t *str,
    ngx_http_waf_rule_parser_t *parser, ngx_http_waf_rule_opt_t *opt)
{
    u_char             *p, *e;
    ngx_int_t           offset;

    static ngx_str_t    sql = ngx_string("sql");
    static ngx_str_t    xss = ngx_string("xss");

    if (str->len - parser->prefix.len < 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid libinj in arguments \"%V\"", str);
        return NGX_ERROR;
    }

    p = str->data + parser->prefix.len;
    e = str->data + str->len;

    offset = ngx_http_waf_parse_rule_decode(cf, opt->p_rule->decode_handlers,
        p, e - 4);
    if (offset == NGX_ERROR) {
        return NGX_ERROR;
    }

    p += offset;

    if ((size_t)(e - p) == sql.len
        && ngx_strncmp(p, sql.data, sql.len) == 0)
    {
        opt->p_rule->str = sql;
        opt->p_rule->handler = ngx_http_waf_rule_str_sqli_handler;

    } else if ((size_t)(e - p) == xss.len
        && ngx_strncmp(p, xss.data, xss.len) == 0)
    {
        opt->p_rule->str = xss;
        opt->p_rule->handler = ngx_http_waf_rule_str_xss_handler;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid libinj args in arguments \"%V\"", str);
        return NGX_ERROR;
    }

    return NGX_OK;
}

// matching-strategy callback function
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

// registered parse directive function
static ngx_http_waf_rule_parser_t  ngx_http_waf_rule_parser_item[] = {
    ......
    {ngx_string("libinj:"),    ngx_http_waf_parse_rule_libinj},
    ......
  }
```

[Back to TOC](#table-of-contents)


Author
======

wenqiang li(vislee)

[Back to TOC](#table-of-contents)

Copyright and License
=====================

This module is licensed under the [GPL](http://www.gnu.org/licenses/licenses.en.html) license.

Copyright (C) 2018, by vislee.

All rights reserved.


[Back to TOC](#table-of-contents)


See Also
========

+ nginx: ngx_http_waf_module based on nginx.
+ naxsi: ngx_http_waf_module has learned a lot of from it.
+ [libinjection](https://github.com/client9/libinjection): ngx_http_waf_module refer to this library.
+ [Hyperscan](https://github.com/intel/hyperscan): replace the PCRE.
+ libmagic: ngx_http_waf_module refer to this library.

[Back to TOC](#table-of-contents)

