<?php

use OAuth2\library\constant\HttpHeader;
use function Composer\Autoload\includeFile;

if(!defined("OAUTH_DS")){
    define("OAUTH_DS",DIRECTORY_SEPARATOR);
}
$vendorPath = realpath(dirname(__DIR__)).OAUTH_DS."vendor".OAUTH_DS."autoload.php";

require_once($vendorPath);

// 定义oauthServer相关配置
$oauthConfig = [
    // 网关认证服根路径
//    "host" => "http://testserver.yichuangzone.com:8091",
    // 另一台认证服
    "host" => "http://test.yichuang.com:8090",
//    "host" => "",
    // 在认证服务中注册本应用的clientId以及client_secret
    "client_id" => "sAWoxlibgN7KJkT2NYwqZUMq8eceG96f",
//    "client_id" => null,
    "client_secret" => "Xwsxwcx74KJhcICrrkwf94iiSddKGSEE",
    // 申明的权限内容
    "scope" => "user_info",
    // 授权码模式回调地址
    "authorize_redirect" => "http://test-php.ermao.com/callback.php",
    // 授权码获取地址
    "authorize_uri" => "/auth/oauth/authorize",
    // token获取地址
    "access_token_uri" => "/auth/oauth/token",
    // 获取用户信息
    "user_info_uri"     => "/auth/user/me",
    // 登出系统
    "logout_sso"        => "/auth/logout",
];

// 允许跨域访问
header(sprintf("%s:%s", HttpHeader::ACCESS_CONTROL_ALLOW_ORIGIN,"*"));
header(sprintf("%s:%s", HttpHeader::ACCESS_CONTROL_ALLOW_METHODS,"GET, POST, PATCH, PUT, DELETE"));
header(sprintf("%s:%s", HttpHeader::ACCESS_CONTROL_ALLOW_HEADERS,"Authorization, Content-Type, If-Match, If-Modified-Since, If-None-Match, If-Unmodified-Since, X-Requested-With,HTTP_X_REQUESTED_WITH"));

if(strtolower($_SERVER["REQUEST_METHOD"]) == "options"){
    http_response_code(204);
    ob_flush();
    die();
}

