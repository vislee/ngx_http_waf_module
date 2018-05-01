Name
=====

[![travis-ci](https://travis-ci.org/vislee/ngx_http_waf_module.svg?branch=master)](https://travis-ci.org/vislee/ngx_http_waf_module)
[![Coverage Status](https://coveralls.io/repos/github/vislee/ngx_http_waf_module/badge.svg?branch=master)](https://coveralls.io/github/vislee/ngx_http_waf_module?branch=master)

**ngx_http_waf_module** 是一个开源的、高效的、规则简单可配置、策略易扩展的nginx WAF模块。


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
ngx_http_waf_module 还处在早期的开发阶段。


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
**语法** *security_rule rule*

**默认:** *no*

**环境:** *http*

配置一条通用的规则，对该`http`下的所有`location`均可见。
规则的格式: `security_rule id:number strategy "s:$TAG:score,$TAG2:score" "z:zones" "note:message";`

+ id: number取值为数字，规则的唯一编码，唯一代表一条规则。在`白名单`和`日志`记录中使用。
+ strategy: 规则策略，有以下几种策略。
  以`str:`开始的是字符串匹配策略。
  以`libinj:`开始的是调用了第三方 (libinjection)[https://github.com/client9/libinjection] 库的策略。
  以`hash:`开始的是计算hash值的策略。
  以`libmagic:`开始的是调用了libmagic库通过检测文件魔数获取文件类型。

  + "str:[decode_func1|decode_func2][!]le@string": [经过decode函数处理后的]字符串[不]小于等于string(字典顺序)
  + "str:[decode_func1|decode_func2][!]ge@string": [经过decode函数处理后的]字符串[不]大于等于string(字典顺序)
  + "str:[decode_func1|decode_func2][!]ct@string": [经过decode函数处理后的]字符串[不]包含string
  + "str:[decode_func1|decode_func2][!]eq@string": [经过decode函数处理后的]字符串[不]等于string
  + "str:[decode_func1|decode_func2][!]sw@string": [经过decode函数处理后的]字符串[不是]以string开始
  + "str:[decode_func1|decode_func2][!]ew@string": [经过decode函数处理后的]字符串[不是]以string结束
  + "str:[decode_func1|decode_func2][!]rx@regex": [经过decode函数处理后的]字符串[不]符合正则表达式
  + "libinj:[decode_func1|decode_func2][!]sql": [经过decode函数处理后的]字符串[不]存在sql注入
  + "libinj:[decode_func1|decode_func2][!]xss": [经过decode函数处理后的]字符串[不]存在xss攻击
  + "hash:[!]md5@hashcode": 字符串的md5值[不]等于hashcode
  + "hash:[!]crc32@hashcode": 字符串的crc32[不]等于hashcode
  + "hash:[!]crc32_long@hashcode": 字符串的crc32_long[不]等于hashcode
  + "libmagic:[!]mime_type@type": 内容的魔数识别[不]等于type

>>**decode_func**: 支持`decode_url`和`decode_base64`函数。通过管道符号(`|`)支持多次decode操作。

>>**!**: 取反。

+ "s:$TAG:score,$TAG2:score": 规则标签打分，通过该配置多条规则可以加权作用。如果不配置，命中该规则请求被BLOCK。

+ zones: 规则策略检测的区域，有以下多种取值。其中`@`代表仅检测对应的key，`#`代表仅检测对应的value。
  + "z:#URL": 检测请求的URL。
  + "z:V_URL:string": 检测是string的URL。
  + "z:X_URL:regex": 检测满足regex正则表达式的URL。
  + "z:[@ | #]ARGS": 检测请求的URL参数，@ARGS表示仅检测参数的key，#ARGS表示仅检测参数的value。
  + "z:V_ARGS:string": 检测请求参数是string参的value。
  + "z:X_ARGS:regex": 检测请求参数满足regex正则表达式的value。
  + "z:[@ | #]HEADERS": 检测请求的头。
  + "z:V_HEADERS:string": 检测请求头是string的value。
  + "z:X_HEADERS:regex": 检测请求头符合regex正则表达式的value。
  + "z:#RAW_BODY": 检测请求的原始(未解码)body。
  + "z:[@ | #]BODY": 检测请求解析后的body，支持urldecode和multipart的解析。
  + "z:V_BODY:string": 检测解析后的body的string的value。
  + "z:X_BODY:regex": 检测body解析后的复合正则表达式的value。
  + "z:#FILE": 检测表单上传的文件内容。
  + "z:X_FILE:regex": 检测表单上传文件名满足正则表达式的内容。

例如：
```nginx
security_rule id:100 "str:decode_base64|decode_url|!eq@foo bar" "s:$ATT:2,$SQLI:1" "z:V_ARGS:foo|#HEADERS" "note:test rule";
```

一个请求的
URL参数foo的value如果先base64解码然后再URL解码的结果不等于"foo bar"，则会对`$ATT` 这个变量累加2分，对`$SQLI`这个变量累加1分。
任一请求头的value如果先base64解码然后再URL解码的结果不等于"foo bar"，则会对`$ATT` 这个变量累加2分，对`$SQLI`这个变量累加1分。

[Back to TOC](#table-of-contents)

security_loc_rule
-----------------
**语法** *security_loc_rule rule*

**默认:** *no*

**环境:** *location*

配置仅对当前`location`可见的规则。

也可以配置屏蔽全局规则的白名单。
白名单的格式：`security_loc_rule "wl:id1,id2" "z:zones" "note:test whitelist";`

[Back to TOC](#table-of-contents)

security_waf
------------
**语法** *security_waf <on|off>*

**默认:** *off*

**环境:** *location*

在对应的`location`开启规则检测。

[Back to TOC](#table-of-contents)


security_check
--------------
**语法** *security_check $tag>threshold <LOG|BLOCK|DROP|ALLOW|$variable>*

**默认:** *no*

**环境:** *location*

设置规则打分的阈值和对应的动作。

支持的动作有：
LOG: 仅记录一条日志。
BLOCK: 拒绝请求，返回403.
DROP: 关闭连接。
ALLOW: 允许通过。
$variable: 满足条件该变量的值为"block"，和map指令配合使用。

例如： 
`security_check "$ATT>5" BLOCK;`  当ATT这个变量的分数累加超过5时，请求被BLOCK。

[Back to TOC](#table-of-contents)

security_log
------------
**语法** *security_log <logfile|off>*

**默认:** *off*

**环境:** *location*

以json格式记录命中的规则和请求。

[Back to TOC](#table-of-contents)


New strategy
===========

如果现有策略不满足需求，新的策略扩展也是非常容易的。仅需要开发两个函数，注册到模块中就可以了。例如调用了libinjection这个库扩展sql注入检测。

[Back to TOC](#table-of-contents)


Author
======

wenqiang li(vislee)

[Back to TOC](#table-of-contents)

Copyright and License
=====================

This module is licensed under the [GPL](http://www.gnu.org/licenses/licenses.zh-cn.html
) license.

Copyright (C) 2018, by vislee.

All rights reserved.

[Back to TOC](#table-of-contents)


See Also
========

[Back to TOC](#table-of-contents)