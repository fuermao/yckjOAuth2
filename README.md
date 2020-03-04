# OAuth2说明
## 依赖

* `guzzlehttp/guzzle` ![Packagist Version](https://img.shields.io/packagist/v/guzzlehttp/guzzle)，文档路径：[Guuzle](https://guzzle-cn.readthedocs.io/zh_CN/latest/request-options.html)
* `php-http/guzzle6-adapter` ![Packagist Version](https://img.shields.io/packagist/v/php-http/guzzle6-adapter)
* `topthink/think-cache` ![Packagist Version](https://img.shields.io/packagist/v/topthink/think-cache)，文档路径：[TP6完全开发手册](https://www.kancloud.cn/manual/thinkphp6_0/1037634)
* `league/oauth2-client` ![Packagist Version](https://img.shields.io/packagist/v/league/oauth2-client)，文档路径：[Basic Usage](https://oauth2-client.thephpleague.com/usage/)
* `phpunit/phpunit` ![Packagist Version (including pre-releases)](https://img.shields.io/packagist/v/phpunit/phpunit) 开发环境测试组件，实际版本信息`V6.5.14`

## 安装说明
### composer安装

```bash
composer require yckj/yckj_oauth2
```

### 异常编码

> 异常`code`基本与`HttpCode`（Http状态码）相匹配，可直接用作响应状态码。

编码 | HttpCode 含义 | 本组件中含义
:---: | :---: | :---:
400 | Bad Request 客户端错误 | 泛指客户端错误或使用了过期AccessToken
401 | Unauthorized 认证失败 | OAuth认证失败
500 | Internal Server Error 服务端异常 | 基本与缓存读取写入失败相关

## 依赖说明

本组件目前主要支持如下功能：

* OAuth2认证仅支持授权码模式
* 支持TP6缓存，依赖默认创建缓存信息（File形式缓存）。支持redis缓存，请参见tp6文档中缓存一节配置。
* 支持自定义设置缓存键。支持删除、获取缓存中的认证信息。
* 依赖遵循PSR-4自动加载机制。

## 使用说明
### 配置信息
#### 缓存配置

缓存支持配置如下所示，需要其他支持，参见tp6文档中缓存一节配置。

```php
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
```

#### SSO OAuth2配置

SSO OAuth2 认证配置如下所示：

```php
return [
    // 1.网关认证服根路径
    "host" => "http://testserver.yichuangzone.com:8091",
    // 2.在认证服务中注册本应用的clientId以及client_secret
    "client_id" => "sAWoxlibgN7KJkT2NYwqZUMq8eceG96f",
    "client_secret" => "Xwsxwcx74KJhcICrrkwf94iiSddKGSEE",
    // 3.申明的权限内容
    "scope" => "user_info",
    // 4.授权码模式回调地址
    "authorize_redirect" => "http://test-php.ermao.com/callback.php",
    // 5.授权码获取地址
    "authorize_uri" => "/auth2/oauth/authorize",
    // 6.token获取地址
    "access_token_uri" => "/auth2/oauth/token",
    // 7.获取用户信息
    "user_info_uri"     => "/auth2/user/me",
    // 8.登出系统
    "logout_sso"        => "/auth2/logout",
    // 9.获取用户菜单权限
    "menus_permission"  => "/auth2/v1/permission",
    // 10.日志文件目录
    "log_path"                  => LOG_PATH,
];
```

### 入口说明

依赖入口文件`YiCKJOAuth2Client.php`，主要通过实例化入口实现相关功能。

```php
try {
    // 实例化入口
    $oauthClient = YiCKJOAuth2Client::getInstance(
    (array)$config->get("OAuthConfig"),(array)$config->get("CacheConfig")
    );
    // 记录sessionId
    $sessionId = session_id();
    // 跳转获取授权码
    $oauthClient->authorizationCode();
} catch (Exception $e) {
    $returnData["s_code"] = $e->getCode();
    $returnData["s_msg"] = $e->getMessage();
    $returnData["s_ts"] = time();
    $returnData["s_data"] = null;
    echo json_encode($returnData);
    ob_flush();
    die;
}
```

### 使用

如果不了解OAuth2认证体系，请参见 **阮一峰** 的博客[《理解OAuth 2.0》](https://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)

1. 调用`authorizationCode()`方法生成授权码；
2. 调用`accessToken()`获取访问令牌AccessToken；
3. 调用`resourceOwnerDetail()`，获取用户信息；
4. 调用`permissions()`，获取权限信息；
5. 调用`refreshAccessToken()` 更新访问令牌；
6. 调用`logout()`方法退出登录；

具体使用demo可参见 `test`目录。

## 异常说明

* `CacheManagerException.php` 缓存异常
* `OAuthClientAuthCodeNotExistException.php` state状态码异常，主要出现在获取accessToken阶段
* `OAuthClientException.php` 依赖统一对外输出异常信息
* `OAuthClientInitializationException.php` 入口初始化异常，主要针对配置不正确。
* `PathNotExistException.php` 路径异常。
