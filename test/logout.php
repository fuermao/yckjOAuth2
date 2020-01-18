<?php
require_once ("index.php");


$oauthClint = \OAuth2\YiCKJOAuth2Client::getInstance($oauthConfig);


try {
    $res = $oauthClint->logout($_GET["access_token"],true);
    $msg = $res?"退出登录成功":"退出登录失败！";
    echo "<pre>";
    print_r($msg);
    echo "<pre/>";
    die;
} catch (\OAuth2\exception\OAuthClientException $e) {
    echo "<pre>";
    print_r($oauthClint);
    echo "<pre/>";
    die;
}