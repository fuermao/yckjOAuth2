<?php

namespace Test\phpunit_test;

use OAuth2\exception\PathNotExistException;
use OAuth2\library\driver\ConfigLoader;
use PHPUnit\Framework\TestCase;

class ConfigLoaderTest extends TestCase
{
	
	public function testInstance(){
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			// 判断配置文件是否加载成功
			$this->assertArrayHasKey("CacheConfig",$config->get(),"加载失败");
			$this->assertTrue("http://testserver.yichuangzone.com:8091" == $config->get("OAuthConfig.host"),"加载配置失败！");
		} catch (PathNotExistException $e) {
			echo $e->getTraceAsString();
		}
	}
	
}
