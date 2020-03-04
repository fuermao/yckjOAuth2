<?php

use OAuth2\exception\OAuthClientException;
use OAuth2\library\logger\Logger;
use OAuth2\YiCKJOAuth2Client;

require_once("index.php");

header("content-type:application/json;charset=utf-8");
$oauthClient = YiCKJOAuth2Client::getInstance($config->get("OAuthConfig"),$config->get("CacheConfig"));

$returnData["s_code"] = 0;
$returnData["s_msg"] = "";
$returnData["s_ts"] = time();
$returnData["s_data"] = null;

try {
	$res = $oauthClient->permissions(session_id());
}catch (OAuthClientException $e){
	Logger::getInstance("test-permission")->write(["Error"=>$e->getMessage()]);
	$returnData["s_code"] = $e->getCode();
	$returnData["s_msg"] = $e->getMessage();
}
echo json_encode($returnData);
ob_flush();
die;