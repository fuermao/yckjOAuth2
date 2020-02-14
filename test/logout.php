<?php
use OAuth2\exception\OAuthClientException;
use OAuth2\library\logger\Logger;
use OAuth2\YiCKJOAuth2Client;

require_once ("index.php");
header("content-type:application/json;charset=utf-8");

$oauthClint = YiCKJOAuth2Client::getInstance($oauthConfig);


$returnData["s_code"] = 0;
$returnData["s_msg"] = "";
$returnData["s_ts"] = time();
$returnData["s_data"] = null;

try {
    $res = $oauthClint->logout($_GET["access_token"],true);
    $msg = $res?"退出登录成功":"退出登录失败！";

    http_response_code(200);
    $returnData["s_code"] = 200;
    $returnData["s_msg"] = $msg;

} catch (OAuthClientException $e) {

    Logger::getInstance("test_logout")->write(["Error"=>$e->getMessage()]);
    $returnData["s_code"] = 500;
    $returnData["s_msg"] = $e->getMessage();

}
echo json_encode($returnData);
ob_flush();
die;