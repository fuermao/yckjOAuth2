<?php

namespace Test;

use OAuth2\exception\PathNotExistException;
use OAuth2\library\driver\ConfigLoader;
use PHPUnit\Framework\TestCase;

class ConfigLoaderTest extends TestCase
{
	
	public function testInstance(){
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			$this->assertArrayHasKey("CacheConfig",$config->get(),"加载失败");
		} catch (PathNotExistException $e) {
			echo $e->getTraceAsString();
		}
	}
	
}
