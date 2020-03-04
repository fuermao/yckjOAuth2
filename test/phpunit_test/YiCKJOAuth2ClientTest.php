<?php

namespace Test;

use League\OAuth2\Client\Token\AccessToken;
use OAuth2\library\driver\ConfigLoader;
use OAuth2\YiCKJOAuth2Client;
use PHPUnit\Framework\TestCase;

class YiCKJOAuth2ClientTest extends TestCase
{
	
	public function testGetStoreAccessToken()
	{
		$sessionId = "g7kopkon560rjqvf4e130gcgkb";
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			
			$ssoClient = YiCKJOAuth2Client::getInstance(
				$config->get("OAuthConfig"),
				$config->get("CacheConfig")
			);
			$accessToken = $ssoClient->getStoreAccessToken($sessionId);
			$refreshToken = $ssoClient->getStoreRefreshToken($sessionId);
			
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
		$accessToken = "2925bf69-c3fc-4468-b016-d22ba7ff276e";
		$sessionId = "g7kopkon560rjqvf4e130gcgkb";
		
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			
			$ssoClient = YiCKJOAuth2Client::getInstance(
				$config->get("OAuthConfig"),
				$config->get("CacheConfig")
			);
			$userInfo = $ssoClient->getStoreUserDetail($sessionId);
			
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
		$sessionId = "g7kopkon560rjqvf4e130gcgkb";
		
		try {
			$config = ConfigLoader::getInstance(TEST_CONF_PATH);
			
			$ssoClient = YiCKJOAuth2Client::getInstance(
				$config->get("OAuthConfig"),
				$config->get("CacheConfig")
			);
			$accessToken = $ssoClient->getStoreAccessToken($sessionId);
			$refreshToken = $ssoClient->getStoreRefreshToken($sessionId);
			
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
}
