<?php

namespace Test\phpunit_test;

use OAuth2\library\logger\Logger;
use PHPUnit\Framework\TestCase;

class LoggerTest extends TestCase
{
	
	public function testInfo()
	{
		$logger = Logger::getInstance("test-logger",LOG_PATH);
		
		$this->assertTrue($logger->info(11111),"写入失败");
		$this->assertTrue($logger->info(0),"写入失败");
		$this->assertTrue($logger->info(true),"写入失败");
		$this->assertTrue($logger->info(false),"写入失败");
		$this->assertTrue($logger->info(["aa"=>"cc","bb"=>[1,2,0]]),"写入失败");
	}
}
