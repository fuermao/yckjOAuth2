<?php
require_once("index.php");

use OAuth2\exception\OAuthClientException;
use OAuth2\library\logger\Logger;
use OAuth2\YiCKJOAuth2Client;

$oauthClient = YiCKJOAuth2Client::getInstance($oauthConfig);


$returnData["s_code"] = 0;
$returnData["s_msg"] = "";
$returnData["s_ts"] = time();
$returnData["s_data"] = null;

// 获取用户信息
try {
    $userInfo = $oauthClient->getResourceOwnerDetail($_GET["access_token"]);
    $returnData["s_code"] = 200;
    $returnData["s_msg"] = "成功获取用户信息";
    $returnData["s_data"] = $userInfo;

} catch (OAuthClientException $e) {
    Logger::getInstance("test_user_detail")->write(["Error"=>$e->getMessage()]);
    $returnData["s_code"] = $e->getCode();
    $returnData["s_msg"] = $e->getMessage();
}
echo json_encode($returnData);
ob_flush();
die;