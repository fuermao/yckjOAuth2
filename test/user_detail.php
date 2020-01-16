<?php
require_once("index.php");

use OAuth2\exception\OAuthClientException;
use OAuth2\library\logger\Logger;
use OAuth2\YiCKJOAuth2Client;


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

// token
$tokenStr = "bd9716c4-96ac-46bf-b67d-a91b29130aea";

// 获取用户信息
try {
    $userInfo = $oauthClient->getResourceOwnerDetail($tokenStr);
    echo "<pre>";
    print_r($userInfo);
    echo "<pre/>";
    die;
} catch (OAuthClientException $e) {
    Logger::getInstance("test_user_detail")->write(["Error"=>$e->getMessage()]);
    echo "<pre>";
    print_r($e->getMessage());
    echo "<pre/>";
    die;
}