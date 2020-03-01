<?php

use OAuth2\YiCKJOAuth2Client;

require_once("index.php");

try {
	$oauthClient = YiCKJOAuth2Client::getInstance(
		(array)$config->get("OAuthConfig"),(array)$config->get("CacheConfig")
	);
	// 记录sessionId
	$sessionId = session_id();
	// 跳转获取授权码
    $oauthClient->authorizationCode();
} catch (Exception $e) {
    $returnData["s_code"] = $e->getCode();
    $returnData["s_msg"] = $e->getMessage();
    $returnData["s_ts"] = time();
    $returnData["s_data"] = null;
    echo json_encode($returnData);
    ob_flush();
    die;
}