<?php

use OAuth2\YiCKJOAuth2Client;

include_once("./index.php");

$oauthConfig = [
    // 认证服根路径
    "host" => "http://test.yichuang.com:8091",
//    "host" => "",
    // 在认证服务中注册本应用的clientId以及client_secret
    "client_id" => "wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe",
//    "client_id" => null,
    "client_secret" => "OcQGLnGe7M4zeq6CRhItvhV63c38uHpj",
    // 申明的权限内容
    "scope" => "user_info",
    // 授权码获取地址
    "authorize_uri" => "/auth2/oauth/authorize",
    // 授权码模式回调地址
    "authorize_redirect" => "http://test-php.ermao.com/callback.php",
    // token获取地址
    "access_token_uri" => "/auth2/oauth/token",
    // 获取用户信息
    "user_info_uri"     => "/auth2/user/me",
];
$oauthClient = YiCKJOAuth2Client::getInstance($oauthConfig);

$oauthClient->refreshAccessToken($_GET["access_token"]);