<?php

namespace Test;

use League\OAuth2\Client\Token\AccessToken;
use OAuth2\library\driver\ConfigLoader;
use OAuth2\YiCKJOAuth2Client;
use PHPUnit\Framework\TestCase;

class YiCKJOAuth2ClientTest extends TestCase
{
	public static $sessionId = "20jfevd5p5s34d80imi72neafo";
	
	public function testGetStoreAccessToken()
	{
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			
			$ssoClient = YiCKJOAuth2Client::getInstance(
				$config->get("OAuthConfig"),
				$config->get("CacheConfig")
			);
			$accessToken = $ssoClient->getStoreAccessToken(self::$sessionId);
			$refreshToken = $ssoClient->getStoreRefreshToken(self::$sessionId);
			
			// 打印下accessToken信息
			print_r($accessToken);
			echo PHP_EOL;
			print_r($refreshToken);
			
			$this->assertTrue($accessToken instanceof AccessToken,"从缓存中获取AccessToken失败！");
			$this->assertTrue($accessToken->getRefreshToken() == $refreshToken,"从缓存中获取RefreshToken失败！");
			
		} catch (\Exception $e) {
			// 打印错误信息
			print_r($e->getMessage());
		}
	}
	
	public function testGetStoreUserDetail()
	{
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			
			$ssoClient = YiCKJOAuth2Client::getInstance(
				$config->get("OAuthConfig"),
				$config->get("CacheConfig")
			);
			$userInfo = $ssoClient->getStoreUserDetail(self::$sessionId);
			
			// 打印下accessToken信息
			print_r($userInfo);
			echo PHP_EOL;
			
			$this->assertTrue(is_array($userInfo) && sizeof($userInfo) > 0,"从缓存中获取用户信息失败！");
			
		} catch (\Exception $e) {
			// 打印错误信息
			print_r($e->getMessage());
		}
	}
	
	public function testGetStoreRefreshToken()
	{
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			
			$ssoClient = YiCKJOAuth2Client::getInstance(
				$config->get("OAuthConfig"),
				$config->get("CacheConfig")
			);
			$accessToken = $ssoClient->getStoreAccessToken(self::$sessionId);
			$refreshToken = $ssoClient->getStoreRefreshToken(self::$sessionId);
			
			// 打印下accessToken信息
			print_r($accessToken);
			echo PHP_EOL;
			print_r($refreshToken);
			echo PHP_EOL;
			
			$this->assertTrue($accessToken instanceof AccessToken,"从缓存中AccessToken！");
			
		} catch (\Exception $e) {
			// 打印错误信息
			print_r($e->getMessage());
		}
	}
	
	public function testGetStorePermission(){
		
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			
			$ssoClient = YiCKJOAuth2Client::getInstance(
				$config->get("OAuthConfig"),
				$config->get("CacheConfig")
			);
			$permission = [];
			if($ssoClient->hasStorePermission(self::$sessionId)){
				$permission = $ssoClient->getStorePermission(self::$sessionId);
			}
			
			// 打印下$permission信息
			print_r($permission);
			echo PHP_EOL;
			$this->assertTrue(is_array($permission) && sizeof($permission) > 0,"从缓存中Permission失败！");
			
		} catch (\Exception $e) {
			// 打印错误信息
			print_r($e->getMessage());
		}
	}
	
	public function testDeleteStorePermission(){
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			
			$ssoClient = YiCKJOAuth2Client::getInstance(
				$config->get("OAuthConfig"),
				$config->get("CacheConfig")
			);
			$res = $ssoClient->deleteStorePermission(self::$sessionId);
			
			// 打印下$permission信息
			var_export($res);
			echo PHP_EOL;
			$this->assertTrue($res,"从缓存中Permission失败！");
			
		} catch (\Exception $e) {
			// 打印错误信息
			print_r($e->getMessage());
		}
	}
}
