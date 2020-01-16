# OAuth2说明
## 依赖

* `guzzlehttp/guzzle` ![Packagist Version](https://img.shields.io/packagist/v/guzzlehttp/guzzle)，文档路径：[Guuzle](https://guzzle-cn.readthedocs.io/zh_CN/latest/request-options.html)
* `php-http/guzzle6-adapter` ![Packagist Version](https://img.shields.io/packagist/v/php-http/guzzle6-adapter)
* `topthink/think-cache` ![Packagist Version](https://img.shields.io/packagist/v/topthink/think-cache)，文档路径：[TP6完全开发手册](https://www.kancloud.cn/manual/thinkphp6_0/1037634)
* `league/oauth2-client` ![Packagist Version](https://img.shields.io/packagist/v/league/oauth2-client)，文档路径：[Basic Usage](https://oauth2-client.thephpleague.com/usage/)

## 安装说明
### composer安装

```bash
composer require yckj/yckj_oauth2
```

## 授权码模式

1. 导向认证服务时，所传参数如下所示

```log
=========================== Log Start ===========================
[Date]:2020-01-10 21:41:02
[Date Timestamp]:1578663662.0048
[Request Http Host]:test-php.ermao.com
[Request Port]:80
[Request Ip Address]:127.0.0.1
[Request Document Uri]:/auth_code.php
[Request Request Uri]:/auth_code.php?response_type=code&state=aaaa&client_id=wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe&scope=user_info&redirect_uri=http%3A%2F%2Ftest-php.ermao.com%2Fcallback.php
[Request Method]:GET
// 请求头信息
[Request Header Accept-Encoding]:gzip, deflate
[Request Header Accept]:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
[Request Header User-Agent]:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Postman/7.15.0 Chrome/66.0.3359.181 Electron/3.1.8-postman.5 Safari/537.36
[Request Header Upgrade-Insecure-Requests]:1
[Request Header Connection]:close
[Request Header Host]:test-php.ermao.com
[Request Header Content-Length]:
[Request Header Content-Type]:
// 携带参数信息
[Request Data(POST)]:[]
[Request Data(GET)]:{"response_type":"code","state":"aaaa","client_id":"wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe","scope":"user_info","redirect_uri":"http:\/\/test-php.ermao.com\/callback.php"}
[Request Data(ALL)]:{"response_type":"code","state":"aaaa","client_id":"wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe","scope":"user_info","redirect_uri":"http:\/\/test-php.ermao.com\/callback.php"}
============================ Log End ============================
```