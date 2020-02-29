<?php

use OAuth2\exception\CacheManagerException;
use OAuth2\library\constant\LogType;
use OAuth2\library\store\StoreFactory;

require (__DIR__.DIRECTORY_SEPARATOR."index.php");


// 获取存储实例信息
$cache = StoreFactory::getInstance();
$currentTime = time();
$expireTime = $currentTime + 3; // 2秒过期

// try {
// 	var_dump($cache->setCacheData("aa", [11, 22], 3));
// } catch (CacheManagerException $e) {
// 	echo "<pre>";
// 	print_r($e->getTrace());
// 	echo "</pre>";
// 	die;
// }

$logPath = __DIR__.DIRECTORY_SEPARATOR."runtime".DIRECTORY_SEPARATOR."log"."/";
// $logPath = "E:\\文档\\对接设备文档\\门禁文档\\";

// 测试日志实例
$logInstance = \OAuth2\library\logger\Logger::getInstance(
	"storeCache",
	$logPath
);


$logInstance->error(LogType::ERROR);
$logInstance->info(LogType::INFO);
$logInstance->fatal(LogType::FATAL);
$logInstance->trace(LogType::TRACE);
$logInstance->debug(LogType::DEBUG);
$logInstance->warn(LogType::WARN);



