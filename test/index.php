<?php

use function Composer\Autoload\includeFile;

if(!defined("OAUTH_DS")){
    define("OAUTH_DS",DIRECTORY_SEPARATOR);
}
$vendorPath = realpath(dirname(__DIR__)).OAUTH_DS."vendor".OAUTH_DS."autoload.php";

// 定义oauthServer相关配置
$oauthConfig = [
    // 认证服根路径
    "host" => "http://testserver.yichuangzone.com:8091",
//    "host" => "",
    // 在认证服务中注册本应用的clientId以及client_secret
    "client_id" => "wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe",
//    "client_id" => null,
    "client_secret" => "OcQGLnGe7M4zeq6CRhItvhV63c38uHpj",
    // 申明的权限内容
    "scope" => "user_info",
    // 授权码模式回调地址
    "authorize_redirect" => "http://test-php.ermao.com/callback.php",
    // 授权码获取地址
    "authorize_uri" => "/auth2/oauth/authorize",
    // token获取地址
    "access_token_uri" => "/auth2/oauth/token",
    // 获取用户信息
    "user_info_uri"     => "/auth2/user/me",
    // 登出系统
    "logout_sso"        => "/auth2/logout"
];
include_once($vendorPath);