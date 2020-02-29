<?php

use OAuth2\exception\CacheManagerException;
use OAuth2\library\store\StoreFactory;

require (__DIR__.DIRECTORY_SEPARATOR."index.php");

$cacheConfig = $cacheConfig = [
	// 默认缓存策略
	'default'	=>	'file',
	'stores'	=>	[
		// 文件类型缓存
		'file'	=>	[
			'type'   => 'File',
			// 缓存保存目录
			'path'   => __DIR__.StoreFactory::OAUTH2_DS.StoreFactory::FILE_CACHE_DIR.StoreFactory::OAUTH2_DS,
			// 缓存前缀
			'prefix' => "",
			// 缓存有效期 0表示永久缓存
			'expire' => 0,
		]
	]
];



// 获取存储实例信息
$cache = StoreFactory::getInstance();

echo "<pre>";
try {
	var_dump($cache->getCacheData("aa"));
} catch (CacheManagerException $e) {

}
echo "</pre>";
die;

