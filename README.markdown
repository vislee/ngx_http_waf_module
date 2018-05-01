Name
====

[![travis-ci](https://travis-ci.org/vislee/ngx_http_waf_module.svg?branch=master)](https://travis-ci.org/vislee/ngx_http_waf_module)
[![Coverage Status](https://coveralls.io/repos/github/vislee/ngx_http_waf_module/badge.svg?branch=master)](https://coveralls.io/github/vislee/ngx_http_waf_module?branch=master)

The **ngx_http_waf_module** is an open-source and high-performance simple-rule easy-extend web application firewall(WAF) module for Nginx.


Table of Contents
=================
* [Name](#name)
* [Status](#status)
* [Install](#install)
* [Example Configuration](#example-configuration)
* [Directives](#directives)
    * [security_rule](#security_rule)
    * [security_loc_rule](#security_loc_rule)
    * [security_waf](#security_waf)
    * [security_check](#security_check)
    * [security_log](#security_log)
* [New strategy](#new-strategy)
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


Directives
==========

security_rule
-------------
**syntax** *security_rule rule*

**default:** *no*

**context:** *http*

Set the general rules. All of `http` containing `location` is visible.
The rule format: `security_rule id:number strategy "s:$TAG:score,$TAG2:score" "z:zones" "note:message";`

+ id: the rules of the ID.
+ strategy: the rules of strategy.
  + str:[decode_func1|decode_func2][!]le@string
  + str:[decode_func1|decode_func2][!]ge@string
  + str:[decode_func1|decode_func2][!]ct@string
  + str:[decode_func1|decode_func2][!]eq@string
  + str:[decode_func1|decode_func2][!]sw@string
  + str:[decode_func1|decode_func2][!]ew@string
  + str:[decode_func1|decode_func2][!]rx@regex
  + libinj:[decode_func1|decode_func2][!]sql
  + libinj:[decode_func1|decode_func2][!]xss
  + hash:[!]md5@hashcode
  + hash:[!]crc32@hashcode
  + hash:[!]crc32_long@hashcode
  + libmagic:mime_type@mime_type

>>decode_func: decode_url or decode_base64

>>!: not. eg: "!eq@test" - Is not equal to 'test'. 

+ zones: the match zone.
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

eg:
```nginx
security_rule id:100 "str:decode_base64|decode_url|!eq@foo bar" "s:$ATT:2,$SQLI:1" "z:V_ARGS:foo|#HEADERS" "note:test rule";
```


[Back to TOC](#table-of-contents)

security_loc_rule
-----------------
**syntax** *security_loc_rule rule*

**default:** *no*

**context:** *location*

Set the location rules.

You can set the screen whitelist of general rule.
The whitelist rule format: `security_loc_rule "wl:id1,id2" "z:zones" "note:test whitelist";`


[Back to TOC](#table-of-contents)

security_waf
------------
**syntax** *security_waf <on|off>*

**default:** *off*

**context:** *location*

Enables or disables this module.

[Back to TOC](#table-of-contents)


security_check
--------------
**syntax** *security_check $tag>threshold <LOG|BLOCK|DROP|ALLOW|$variable>*

**default:** *no*

**context:** *location*

Set rule score threshold and action.

[Back to TOC](#table-of-contents)

security_log
------------
**syntax** *security_log <logfile|off>*

**default:** *off*

**context:** *location*

[Back to TOC](#table-of-contents)


New strategy
===========

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
+ libinjection: ngx_http_waf_module refer to this library.
+ libmagic: ngx_http_waf_module refer to this library.

[Back to TOC](#table-of-contents)

