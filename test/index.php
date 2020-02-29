<?php

use OAuth2\exception\PathNotExistException;
use OAuth2\library\constant\HttpHeader;
use OAuth2\library\driver\ConfigLoader;
use OAuth2\library\Tools;

if(!defined("OAUTH_DS")){
    define("OAUTH_DS",DIRECTORY_SEPARATOR);
}
$vendorPath = realpath(dirname(__DIR__)).OAUTH_DS."vendor".OAUTH_DS."autoload.php";
// 开启session
session_start();
require_once($vendorPath);

// 允许跨域访问
header(sprintf("%s:%s", HttpHeader::ACCESS_CONTROL_ALLOW_ORIGIN,"*"));
header(sprintf("%s:%s", HttpHeader::ACCESS_CONTROL_ALLOW_METHODS,"GET, POST, PATCH, PUT, DELETE"));
header(sprintf("%s:%s", HttpHeader::ACCESS_CONTROL_ALLOW_HEADERS,"Authorization, Content-Type, If-Match, If-Modified-Since, If-None-Match, If-Unmodified-Since, X-Requested-With,HTTP_X_REQUESTED_WITH"));

// 定义全局常量
define("ROOT_PATH",__DIR__.DIRECTORY_SEPARATOR);
define("TEST_CONF_PATH",ROOT_PATH."conf".DIRECTORY_SEPARATOR);
// 运行时目录
define("RUNTIME_PATH",ROOT_PATH."runtime".DIRECTORY_SEPARATOR);
define("LOG_PATH",RUNTIME_PATH."log".DIRECTORY_SEPARATOR);
define("CACHE_PATH",RUNTIME_PATH."cache".DIRECTORY_SEPARATOR);

// 加载配置文件，并获取数组
try {
	$config = ConfigLoader::getInstance(TEST_CONF_PATH);
} catch (PathNotExistException $e) {
	$error["err_msg"] = $e->getMessage();
	$error["err_file"] = $e->getFile();
	$error["err_line"] = $e->getLine();
	$error["trace_info"] = $e->getTraceAsString();
	http_response_code(500);
	header("Content-Type: application/json");
	echo json_encode($error,JSON_UNESCAPED_UNICODE);
	ob_flush();
	die;
}
if(array_key_exists("REQUEST_METHOD",$_SERVER) && strtolower($_SERVER["REQUEST_METHOD"]) == "options"){
    http_response_code(204);
    ob_flush();
    die();
}