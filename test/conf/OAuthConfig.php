<?php
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
	"authorize_uri" => "/auth/oauth/authorize",
	// 6.token获取地址
	"access_token_uri" => "/auth/oauth/token",
	// 7.获取用户信息
	"user_info_uri"     => "/auth/user/me",
	// 8.登出系统
	"logout_sso"        => "/auth/logout",
	// 9.获取用户菜单权限
	"menus_permission"  => "/auth/v1/permission",
    // 10.日志文件目录
    "log_path"                  => LOG_PATH,
];