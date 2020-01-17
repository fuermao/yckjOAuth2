<?php
require_once("index.php");

use OAuth2\exception\OAuthClientAuthCodeNotExistException;
use OAuth2\exception\OAuthClientException;
use OAuth2\library\logger\Logger;
use OAuth2\YiCKJOAuth2Client;

//// 重定向获取access_token等信息
//$oauthConfig = [
//    // 认证服根路径
//    "host" => "http://test.yichuang.com:8091",
//    // 在认证服务中注册本应用的clientId以及client_secret
//    "client_id" => "wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe",
//    "client_secret" => "OcQGLnGe7M4zeq6CRhItvhV63c38uHpj",
//    // 申明的权限内容
//    "scope" => "user_info",
//    // 授权码获取地址
//    "authorize_uri" => "/auth2/oauth/authorize",
//    // 授权码模式回调地址
//    "authorize_redirect" => "",
//    // token获取地址
//    "access_token_uri" => "/auth2/oauth/token",
//    // 获取用户信息
//    "user_info_uri"     => "/auth2/user/me"
//];
//if(array_key_exists("code",$_GET) && array_key_exists("state",$_GET)){
//    // 记录重定向返回的数据信息
//    Logger::getInstance("code_redirect")->write([]);
//
//    $data["grant_type"] = "authorization_code";
//    $data["code"] = $_GET["code"];
//    $data["state"] = $_GET["state"];
//    $data["redirect_uri"] = "http://test-php.ermao.com/callback.php";
//    $data["client_id"] = "wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe";
//    $data["client_secret"] = "OcQGLnGe7M4zeq6CRhItvhV63c38uHpj";
//    $data["scope"] = $oauthConfig["scope"];
//
//    $httpClient = new Client([
//        "base_uri" => $oauthConfig["host"],
//    ]);
//
//    $header["Content-Type"] = "application/x-www-form-urlencoded";
//    $header["Authorization"] = sprintf("Basic %s",base64_encode($oauthConfig["client_id"].":".$oauthConfig["client_secret"]));
//
//    try {
//        $response = $httpClient->request("POST",$oauthConfig["access_token_uri"],[
//            "form_params" => $data,
//            "headers" => $header
//        ]);
//        $logData["Response Http Code"] = $response->getStatusCode();
//        $logData["Response Body"] = $response->getBody()->getContents();
//    }catch (Exception $exception){
//        $logData["Response Http Code"] = $response->getStatusCode();
//        $logData["Exception"] = $exception->getMessage();
//    } finally {
//        Logger::getInstance("access_token")->write($logData);
//    }
//}
$oauthClient = YiCKJOAuth2Client::getInstance($oauthConfig);

try {
    $accessToken = $oauthClient->getAccessToken();
    echo "<pre>";
    print_r($accessToken);
    echo "<pre/>";
    die;
} catch (OAuthClientAuthCodeNotExistException $e) {
    Logger::getInstance("test_callback")->write(["Error"=>$e->getMessage()]);
} catch (OAuthClientException $e) {
    Logger::getInstance("test_callback")->write(["Error"=>$e->getMessage()]);
} catch (throwable $e) {
    Logger::getInstance("test_callback")->write(["Error"=>$e->getMessage()]);
}