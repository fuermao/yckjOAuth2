<?php
return [
	// 默认缓存策略
	'default'	=>	'file',
	'stores'	=>	[
		// 文件类型缓存
		'file'	=>	[
			'type'   => 'File',
			// 缓存保存目录
			'path'   => CACHE_PATH,
			// 缓存前缀
			'prefix' => "",
			// 缓存有效期 0表示永久缓存
			'expire' => 0,
		],
		// redis缓存设置
		'redis'	=>	[
			'type'   => 'redis',
			'host'   => '127.0.0.1',
			'port'   => 6379,
			'prefix' => '',
			'expire' => 0,
		],
	],
];