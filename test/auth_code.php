<?php
require_once("index.php");


use OAuth2\exception\OAuthClientException;
use OAuth2\YiCKJOAuth2Client;



// 记录初始请求信息
//=========================== Log Start ===========================
//[Date]:2020-01-10 21:41:02
//[Date Timestamp]:1578663662.0048
//[Request Http Host]:test-php.ermao.com
//[Request Port]:80
//[Request Ip Address]:127.0.0.1
//[Request Document Uri]:/auth_code.php
//[Request Request Uri]:/auth_code.php?response_type=code&state=aaaa&client_id=wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe&scope=user_info&redirect_uri=http%3A%2F%2Ftest-php.ermao.com%2Fcallback.php
//[Request Method]:GET
//[Request Header Accept-Encoding]:gzip, deflate
//[Request Header Accept]:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
//[Request Header User-Agent]:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Postman/7.15.0 Chrome/66.0.3359.181 Electron/3.1.8-postman.5 Safari/537.36
//[Request Header Upgrade-Insecure-Requests]:1
//[Request Header Connection]:close
//[Request Header Host]:test-php.ermao.com
//[Request Header Content-Length]:
//[Request Header Content-Type]:
//[Request Data(POST)]:[]
//[Request Data(GET)]:{"response_type":"code","state":"aaaa","client_id":"wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe","scope":"user_info","redirect_uri":"http:\/\/test-php.ermao.com\/callback.php"}
//[Request Data(ALL)]:{"response_type":"code","state":"aaaa","client_id":"wjz0hTNcTHvx88aexQ9pKeezuq4ldhGe","scope":"user_info","redirect_uri":"http:\/\/test-php.ermao.com\/callback.php"}
//============================ Log End ============================


//// 获取参数信息
//$redirectUrl = $_GET["redirect_uri"];
//// 生成数据
//$sendData["code"] = Tools::randomString(6,true);
//$sendData["state"] = Tools::randomString(4,true);
//
//$queryStr = "?";
//foreach ($sendData as $key=>$sendDatum) {
//    $queryStr.=sprintf("%s=%s&",$key,$sendDatum);
//}
//$queryStr = rtrim($queryStr,"&");
//
//$redirectUrl.=$queryStr;
//
//// 重定向至回调地址
//$httpClient = new Client([
//    "base_uri" => $redirectUrl
//]);
//$httpClient->request("GET","",[
//        'max'             => 5,
//        'strict'          => false,
//        'referer'         => true,
//        'protocols'       => ['http', 'https'],
//        'track_redirects' => false
//]);

$oauthClient = YiCKJOAuth2Client::getInstance($oauthConfig);

try {
    $token = $oauthClient->authorizationCode();
} catch (OAuthClientException $e) {
}