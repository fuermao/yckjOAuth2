<?php
require_once("index.php");

use OAuth2\exception\OAuthClientException;
use OAuth2\library\logger\Logger;
use OAuth2\YiCKJOAuth2Client;

$oauthClient = YiCKJOAuth2Client::getInstance($oauthConfig);

// 获取用户信息
try {
    $userInfo = $oauthClient->getResourceOwnerDetail($_GET["access_token"]);
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