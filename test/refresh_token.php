<?php

use League\OAuth2\Client\Token\AccessToken;
use OAuth2\exception\OAuthClientException;
use OAuth2\library\logger\Logger;
use OAuth2\YiCKJOAuth2Client;


include_once("./index.php");
header("content-type:application/json;charset=utf-8");

$oauthClient = YiCKJOAuth2Client::getInstance($config->get("OAuthConfig"),$config->get("CacheConfig"));

try{
    $accessToken = $oauthClient->refreshAccessToken(session_id());

    if($accessToken instanceof AccessToken){
        http_response_code(200);
        echo json_encode($accessToken);
        ob_flush();
        die;
    }else{
        http_response_code(401);
        $returnData["s_code"] = -1;
        $returnData["s_msg"] = "登录失败！";
    }

}catch(OAuthClientException $e){
    http_response_code($e->getCode());
    $returnData["s_code"] = 401;
    $returnData["s_msg"] = $e->getMessage();
    Logger::getInstance("test_refresh_token")->write(["Error"=>$e->getMessage()]);
}

echo json_encode($returnData);
flush();
ob_flush();
die;