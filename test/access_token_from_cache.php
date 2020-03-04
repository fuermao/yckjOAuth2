<?php

use OAuth2\exception\OAuthClientException;
use OAuth2\YiCKJOAuth2Client;

require ("index.php");

header("content-type:application/json;charset=utf-8");
$oauthClient = YiCKJOAuth2Client::getInstance($config->get("OAuthConfig"),$config->get("CacheConfig"));


$sessionId = session_id();
// 从缓存中获取accessToken

try {
	$accessToken = $oauthClient->getStoreAccessToken($sessionId);
	$refreshToken = $oauthClient->getStoreRefreshToken($sessionId);
	$userInfo = $oauthClient->getStoreUserDetail($sessionId);
	$returnData["Access Token"] = $accessToken;
	$returnData["Refresh Token"] = $refreshToken;
	$returnData["User Info"] = $userInfo;
} catch (OAuthClientException $e) {
	$returnData["s_code"] = $e->getCode();
	$returnData["s_msg"] = $e->getMessage();
}
echo json_encode($returnData);
ob_flush();
die;