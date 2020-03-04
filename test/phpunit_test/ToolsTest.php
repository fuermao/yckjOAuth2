<?php
namespace Test\phpunit_test;

use OAuth2\library\entity\ResponseEntity;
use OAuth2\library\tools\ArraysToObject;
use PHPUnit\Framework\TestCase;

class ToolsTest extends TestCase
{
	
	public function testArrayToObject()
	{
		$testArr = [
			"code"  => 200,
			"msg"   => "操作成功！",
			"data"  => [
				"aa" => "bb",
				"cc" => "dd"
			],
			"error" => "bb"
		];
		$instance = ArraysToObject::getInstance(ResponseEntity::class,$testArr);
		$instance->exchangeToObject();
		$code = $instance->invokeMethod("getCode");
		$msg = $instance->invokeMethod("getMsg");
		
		// 断言
		$this->assertEquals(200,$code,"获取code失败！");
		$this->assertEquals("操作成功！",$msg,"获取msg失败！");
	}
}
