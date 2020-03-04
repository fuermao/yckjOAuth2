<?php


namespace OAuth2;


use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use OAuth2\exception\CacheManagerException;
use OAuth2\exception\OAuthClientAuthCodeNotExistException;
use OAuth2\exception\OAuthClientException;
use OAuth2\exception\OAuthClientInitializationException;
use OAuth2\library\constant\HttpHeader;
use OAuth2\library\constant\MediaType;
use OAuth2\library\entity\ResponseEntity;
use OAuth2\library\entity\ResponseEntityGateway;
use OAuth2\library\logger\Logger;
use OAuth2\library\store\StoreFactory;
use OAuth2\library\tools\ArraysToObject;
use OAuth2\library\YiChKeJiPostAuthOptionProvider;
use ReflectionException;
use UnexpectedValueException;


class YiCKJOAuth2Client
{
    /**
     * 实例信息
     * @var YiCKJOAuth2Client
     */
    private static $instance;

    /**
     * 缓存管理
     * @var StoreFactory
     */
    private $cacheManager;

    /**
     * 授权服务实例对象
     * @var GenericProvider
     */
    private $provider;

    /**
     * GenericProvider OAuth配置
     * @var array
     */
    private $oauthConfig = [
        // 应用Id
        "clientId"                  => "",
        // 应用秘钥
        "clientSecret"              => "",
        // 重定向地址 完整地址，如：http://test.xxxx.com/callback.php
        "redirectUri"               => "",
        // 获取授权码地址 完整地址，如：http://test.xxxx.com/oauth/authorize
        "urlAuthorize"              => "",
        // 获取access_token地址 完整地址，如：http://test.xxxx.com/oauth/token
        "urlAccessToken"            => "",
        // 获取当前授权用户信息 完整地址，如：http://test.xxxx.com/user/me
        "urlResourceOwnerDetails"   => "",
        // 配置的权限 根据系统情况而定 ，如：user_info
        "scopes"                    => "",
        // 登出SSO系统 完整地址，如：http://test.xxxx.com/logout
        "logoutSSO"                 => "",
	    // 获取用户权限信息
	    "userPermission"           => "",
    ];

    /**
     * 允许外部输入认证配置信息键名信息，以及内部 $oauthConfig 配置对应关系
     * 该变量的作用主要是检测外部输入键名是否匹配。
     * $key                         => $value
     * $key为对外输出配置名称            $value 是对内配置名称，如果配置携带了true，则代表该配置将和host key
     *                                进行拼装组成完整的地址名称
     *
     * @var array
     */
    private static $oauthConfigInput = [
        // 1.认证服务根路径，如: http://test.xxxxxx.com 或 http://192.***.***.10:8091 端口形式
        "host"                      => "",
        // 2.在认证服务中注册本应用的clientId以及client_secret
        "client_id"                 => "clientId",
        "client_secret"             => "clientSecret",
        // 3.申明的权限内容
        "scope"                     => "scopes",
        // 4.授权码模式回调地址
        "authorize_redirect"        => "redirectUri",
        // 5.授权码获取地址
        "authorize_uri"             => "urlAuthorize,true",
        // 6.token获取地址
        "access_token_uri"          => "urlAccessToken,true",
        // 7.获取用户信息
        "user_info_uri"             => "urlResourceOwnerDetails,true",
        // 8.登出SSO系统
        "logout_sso"                => "logoutSSO,true",
	    // 9.获取用户权限信息
	    "menus_permission"          => "userPermission,true",
	    // 10.日志文件目录
	    "log_path"                  => "",
    ];

    /**
     * 缓存标签名称
     */
    const cache_state_tag = "yckj_state_code";

    /**
     * 缓存access token标签名称
     */
    const cache_access_token_tag = "yckj_oauth2_access_token";

    /**
     * 缓存 refresh token标签名称
     */
    const cache_refresh_token_tag = "yckj_oauth2_refresh_token";

    /**
     * 缓存user detail（用户信息）标签名称
     */
    const cache_user_detail_tag = "yckj_user_detail";
	
	/**
	 * 缓存用户权限信息标签
	 */
    const cache_user_permission_tag = "yckj_user_permission";

    /**
     * 缓存策略，参见 topthink/cache 组件说明或 tp6框架缓存章节
     * @var array
     */
    private $cacheConfig = [
        'default'	=>	'file',
        'stores'	=>	[
            'file'	=>	[
                'type'   => 'File',
                // 缓存保存目录
                'path'   => "",
                // 缓存前缀
                'prefix' => 'oauth',
                // 缓存有效期 0表示永久缓存
                'expire' => 0,
            ],
            'redis'	=>	[
                'type'   => 'redis',
                'host'   => '127.0.0.1',
                'port'   => 6379,
                'prefix' => '',
                'expire' => 0,
            ],
        ],
    ];

    /**
     * @var Logger 日志实例
     */
    private $logInstance;

    /**
     * @var string 日志文件名称
     */
    private static $logFileName = "oauth_process";
	
	/**
	 * 毅创空间OAuth2构造函数
	 * 缓存配置设置以及缓存中的日志文件目录设置
	 * YiCKJOAuth2Client constructor.
	 *
	 * @param array $cacheConfig 缓存配置
	 * @param array $oauthConfig SSO客户端配置
	 */
    protected function __construct(array $cacheConfig=[],array $oauthConfig = []){
    	// +++++++++++++++++++++++++++++++++++ 第一步 +++++++++++++++++++++++++++++++++++ //
    	// ++++++++++++++++++++++ 校验参数所传 oauth SSO 参数是否正确 ++++++++++++++++++++++ //
	    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ //
	    $this->checkOAuthConfig($oauthConfig);
	    
	    // +++++++++++++++++++++++++++++++++++ 第二步 +++++++++++++++++++++++++++++++++++ //
	    // +++++++++++++++++++++++++++++++ 实例化缓存工厂 ++++++++++++++++++++++++++++++++ //
	    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ //
        // 初始化缓存策略，缓存配置设置以及缓存中的日志文件目录设置
        $this->cacheManager = StoreFactory::getInstance($cacheConfig,$oauthConfig["log_path"]);
    }

    /**
     * 获取实例信息
     * @param array $oauthConfig OAuth配置参数
     * @param array $cacheConfig
     * @return YiCKJOAuth2Client
     */
    public final static function getInstance(array $oauthConfig,array $cacheConfig=[]): YiCKJOAuth2Client{
        // 获取毅创SSO示例
    	if(self::$instance == null || empty(self::$instance)){
		    // 将缓存实例化
            self::$instance = new self($cacheConfig,$oauthConfig);
        }
        // 初始化 SSO 实例
        self::$instance->init($oauthConfig);
        // 公有初始化信息(该函数可以继承)
        self::$instance->initialization();
        return self::$instance;
    }
	
	/**
	 * 验证oauth配置是否正确
	 * @param array $oauthConfig
	 */
    private function checkOAuthConfig(array $oauthConfig): void{
	    // 传递进来的参数与默认配置参数相比较，取差集。差集为缺失的必传参数
	    $missKeysArr = array_diff_key(self::$oauthConfigInput,$oauthConfig);
	    // 判断必传参数是否有缺失
	    if(!empty($missKeysArr) && is_array($missKeysArr)){
		    $errMsg = sprintf("配置参数[%s]缺失，初始化失败！",implode(",",array_keys($missKeysArr)));
		    throw new OAuthClientInitializationException($errMsg,500);
	    }
	    // 判断必传参数中是否存在空值
	    if(in_array("",$oauthConfig,true) || in_array(null,$oauthConfig,true)){
		    $valEmptyKey = array_search("",$oauthConfig,true)?array_search("",$oauthConfig,true):array_search(null,$oauthConfig,true);
		    $errMsg = sprintf("配置中[%s]值为空，初始化失败！",$valEmptyKey);
		    throw new OAuthClientInitializationException($errMsg,500);
	    }
    }
    
	/**
	 * 私有初始化配置
	 * @param array $oauthConfig OAuth配置
	 */
    private function init(array $oauthConfig): void{
	    // 翻转输出配置与输入配置
	    $arr = array_flip(self::$oauthConfigInput);
	    // 如果$config不为空，则合并两个数组(中间可能存在不会使用的配置值)
	    foreach ($arr as $key=>$item) {
		    if(empty($key)){
			    continue;
		    }
		    if(preg_match_all("/^([a-z]*)([,]true)$/i",$key)){
			    list($key,$res) = explode(",",$key);
			    if((boolean)$res){
				    $this->oauthConfig[$key] = $oauthConfig["host"].$oauthConfig[$item];
			    }
		    }else{
			    $this->oauthConfig[$key] = $oauthConfig[$item];
		    }
	    }
        $this->provider = new GenericProvider($this->oauthConfig);
	    $logPath = array_key_exists("log_path",$oauthConfig) && !empty($oauthConfig["log_path"])?$oauthConfig["log_path"]:"";
	    // 初始化日志实例 两个条件：日志实例为空或者null 或者日志根路径与当前日志实例根路径不同，则初始化日志实例
	    $this->logInstance = Logger::getInstance(self::$logFileName,$logPath);
    }

    /**
     * 公有初始化配置
     */
    protected function initialization(): void {
    
    }
	
	/**
	 * 授权码模式获取授权码
	 *
	 * @throws OAuthClientException
	 */
    public function authorizationCode()
    {
    	// 如果请求中携带了其他参参数
	    $params = [];
	    if(!empty($_GET)){
	    	// 合并参数
	        $params = array_merge($params,$_GET);
	    }
        // 获取认证服完整地址，将原始请求中携带了参数则一同转发
        $getCodeUrl = $this->provider->getAuthorizationUrl($params);
        // 将state string存储起来
        $statStr = $this->provider->getState();
        // 记录下请求信息以及oauth配置
        $logData = array_merge($this->oauthConfig,[
            "OAuth stage"=>"请求获取授权码阶段【auth_code】",
            // 状态码
            "Service States Code"=>sprintf("auth_code = %s",$statStr)
        ]);
        // 记录日志信息
        $this->logInstance->write($logData);
        // 将stateStr存储与缓存中，并设置过期时间 600s = 10分钟
	    try {
		    $this->storeStateCode($this->getStateCodeKey($statStr),$statStr);
	    } catch (exception\CacheManagerException $e) {
	    	throw new OAuthClientException($e->getMessage(),$e->getCode());
	    }
	    // 导向认证服务器
        header(sprintf("%s:%s",HttpHeader::JAVASCRIPT_AJAX,"XMLHttpRequest"));
        header("Location: ".$getCodeUrl);
        // 跳转后退出程序
        exit();
    }
	
	/**
	 * 授权码模式通过 auth_code 交换 access_token
	 *
	 * @param string $cacheKey      缓存AccessToken的键值
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return AccessToken
	 */
    public function accessToken(string $cacheKey): AccessToken {
    	// 校验缓存key是否存在
        $logData["OAuth stage"]="授权码交换令牌阶段【access_token】";
        // 从GET传参中获取参数信息解码并过滤
        // 授权码
        $authCode = array_key_exists("code",$_GET)?htmlspecialchars(trim(urldecode($_GET["code"]))):"";
        // 状态码
        $stateStr = array_key_exists("state",$_GET)?htmlspecialchars(trim(urldecode($_GET["state"]))):"";
        if(empty($authCode) || empty($stateStr)){
            $msg = "授权码(code)或状态码(state)缺失！";
            $this->logInstance->error($msg);
            throw new OAuthClientException($msg,401);
        }
        // 判断缓存中是否存在state字符串
        try {
            $stateExistRes = $this->getStateCode($this->getStateCodeKey($stateStr));
            if(empty($stateExistRes)){
            	$msg = "状态码（state【".$stateStr."】）不存在或不匹配";
                $this->logInstance->error($msg);
                throw new OAuthClientAuthCodeNotExistException($msg,401);
            }
            // 拼装请求
            // 获取授权码对象
            $providerOptions = new YiChKeJiPostAuthOptionProvider($this->oauthConfig["clientId"],$this->oauthConfig["clientSecret"]);
            // 设置请求头以及request body中必须的请求参数
            $this->provider->setOptionProvider($providerOptions);
            // 拼装请求参数数组
            $requestData["code"] = $authCode;
            $requestData["scope"] = $this->oauthConfig["scopes"];

            // 日志参数
            $logData["Request Options"] = $providerOptions->getAccessTokenOptions(GenericProvider::METHOD_POST,$requestData);
            // 授权码
            $accessToken = $this->provider->getAccessToken("authorization_code",$requestData);
            // 判断是否成功获取 access_token
            if(!($accessToken instanceof AccessToken)){
                $msg =  "获取access_token失败！".mb_strcut((string)$accessToken,0,20,"uft8");
                $this->logInstance->error($msg);
                throw new OAuthClientException($msg,401);
            }
            // 使用thinkphp的缓存策略
            $logData["Access Token Result"] = "成功获取Token";
            $logData["Access Token"] = (array)$accessToken->jsonSerialize();
            $logData["Refresh Access Token"] = $accessToken->getRefreshToken();

            // 将token信息存储起来
	        $logData["Result"] = $this->storeAccessToken($cacheKey,$accessToken)?"存储accessToken成功！" : "存储accessToken失败！" ;
            $this->logInstance->write($logData);
            return $accessToken;
        } catch (IdentityProviderException $e) {
            if(is_array($e->getResponseBody())){
                $exceptionMsg = implode(",",array_values($e->getResponseBody()));
            }else{
                $exceptionMsg = $e->getResponseBody();
            }
            $errMsg = sprintf("获取access_token失败！%s",$exceptionMsg);
            $this->logInstance->error($errMsg);
            throw new OAuthClientException($errMsg,500);
        } catch (OAuthClientAuthCodeNotExistException $e){
            $exceptionMsg = $e->getMessage();
	        $this->logInstance->error($exceptionMsg);
            throw new OAuthClientException($exceptionMsg,$e->getCode());
        } catch (exception\CacheManagerException $e) {
	        $this->logInstance->error($e->getMessage());
	        throw new OAuthClientException($e->getMessage(),$e->getCode());
        }
    }
	
	/**
	 * 获取当前授权用户信息
	 *
	 * @param string $accessTokenCacheKey AccessToken缓存键
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return array
	 */
    public function resourceOwnerDetail(string $accessTokenCacheKey):array {
        $logData["OAuth stage"]="获取用户信息阶段【user_detail】";
        $this->logInstance->info($this->hasStoreUserDetail($accessTokenCacheKey));
        // 尝试从缓存中获取
        if($this->hasStoreUserDetail($accessTokenCacheKey)){
            $userInfo = $this->getStoreUserDetail($accessTokenCacheKey);
            $logData["Get User Info From Cache"] = "true";
            $logData["User Info"] = $userInfo;
            $this->logInstance->write($logData);
            return $userInfo;
        }
        // 从认证服务获取用户信息
        else{
            try {
                // 获取accessToken
                $accessToken = $this->getStoreAccessToken($accessTokenCacheKey);
                // 设置参数
                $this->provider->setOptionProvider(new YiChKeJiPostAuthOptionProvider($this->oauthConfig["clientId"],$this->oauthConfig["clientSecret"]));
                // 获取用户信息
                $userInfo = $this->provider->getResourceOwner($accessToken);
                if(!($userInfo instanceof GenericResourceOwner) || !$userInfo){
                    $errMsg = "获取用户信息失败！";
                    $this->logInstance->error($logData);
                    throw new OAuthClientException($errMsg,500);
                }
                // 将用户信息写入缓存中
                $this->storeUserDetail($accessTokenCacheKey,$userInfo);
                // 将完整的解析
                $logData["User Info"] = (array)$userInfo->toArray();
                $this->logInstance->write($logData);
                return (array)$userInfo->toArray();
            } catch (UnexpectedValueException $exception){
                $errMsg = sprintf("获取用户信息失败，认证服响应非json格式，导致无法解析！%s",$exception->getMessage());
                // 获取用户信息失败
                $this->logInstance->error($errMsg);
                throw new OAuthClientException($errMsg,500);
            }
        }
    }
	
	/**
	 * 根据AccessToken获取用户菜单权限数据
	 *
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return array
	 */
    public function permissions(string $accessTokenCacheKey):array {
	    $logData["OAuth stage"]="获取用户授权信息阶段【user_permission】";
        // 从缓存中获取accessToken信息
	    $accessToken = $this->getStoreAccessToken($accessTokenCacheKey);
	    $accessTokenStr = $accessToken->getToken();
	    
	    // 尝试从缓存中获取数据
	    if($this->hasStorePermission($accessTokenCacheKey)){
	    	$permission = $this->getStorePermission($accessTokenCacheKey);
		    $logData["Get User Info From Cache"] = "true";
		    $logData["User Info"] = $permission;
	        return $this->getStorePermission($accessTokenCacheKey);
	    }
	    try {
		    $httpClient = new Client();
		    $response = $httpClient->request(
			    "GET",
			    // 请求权限的地址
			    $this->oauthConfig["userPermission"],
			    // 发送的请求头信息
			    [
			    	"headers"   => [
					    HttpHeader::AUTHORIZATION=>sprintf("Bearer %s",$accessTokenStr)
				    ],
			    ]
		    );
		    // 尝试解析json数据
		    $responseDataArr = json_decode($response->getBody()->getContents(),true);
		    if (empty($responseDataArr) || !is_array($responseDataArr) || sizeof($responseDataArr) == 0){
		    	// 不是则抛出异常信息
			    $errorMsg = "请求用户权限信息失败！无法解析非JSON格式权限信息！".mb_strcut($response->getBody()->getContents(),0,50)."...";
			    // 记录日志信息
			    $this->logInstance->error($errorMsg);
		        throw new OAuthClientException($errorMsg,500);
		    }
		    // 将消息转换为实体
		    $response = null;
		    // 尝试解析两种信息实体
		    $responseEntityArr = [
		    	// 第一种为非网关返回，即直接返回数据
		    	ResponseEntity::class,
			    // 为网关返回信息
			    ResponseEntityGateway::class
		    ];
		    $permission = [];
		    // 解析返回数据
		    foreach ($responseEntityArr as $key=>$item) {
			    try {
				    $tools = ArraysToObject::getInstance($item,$responseDataArr)->exchangeToObject();
				    $code = $tools->invokeMethod("getCode");
				    $msg = $tools -> invokeMethod("getMsg");
				    if($code == 200 || $code == 0){
				        $permission = (array)$tools->invokeMethod("getData");
					    // 缓存数据内容
					    $this->storePermission($accessTokenCacheKey,$permission);
				    }else{
				    	$errorMsg = "获取用户权限失败！失败原因：".$msg."请联系上级管理员对账号进行授权本服务角色！";
				    	// 记录错误日志
					    $this->logInstance->error($errorMsg);
					    throw new OAuthClientException($errorMsg,401);
				    }
			    } catch (ReflectionException $e) {
			    	if($key == sizeof($responseEntityArr) - 1){
			    		$msg = "无法解析消息格式！".$e->getMessage();
			    	    throw new OAuthClientException($msg,500);
				    }
			    }
		    }
		    return $permission;
	    } catch (ClientException $e){
	    	$responseBody = $e->getResponse()->getBody()->getContents();
		    $responseBodyArr = json_decode($responseBody,true);
		    if(array_key_exists("error",$responseBodyArr) && array_key_exists("error_description",$responseBodyArr)){
		        $msg = "请求用户权限信息失败！".$responseBodyArr["error_description"];
		    }else{
			    $msg = "请求用户权限信息失败！".mb_strcut($responseBody,0);
		    }
	        $this->logInstance->error($msg);
	        throw new OAuthClientException($msg,$e->getResponse()->getStatusCode());
	    }
    }
	
	/**
	 * 根据用户之前的过期的accessTokenString
	 * 查询该access token所对应的Refresh Token来请求认证服务更新 access token
	 *
	 * @param string $accessTokenCacheKey 缓存refreshToken的键=>对应缓存accessToken的键
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return AccessToken
	 */
    public function refreshAccessToken(string $accessTokenCacheKey):AccessToken{
        $logData["OAuth stage"]="刷新令牌阶段【refresh_access_token】";
        try {
            $refreshToken = $this->getStoreRefreshToken($accessTokenCacheKey);
            if(empty($refreshToken) || !$refreshToken || $refreshToken == null){
                $errMsg = "access token 无法获取 refresh token！请核实Oauth Client是否具有获取refresh token权限！其次联系管理员清除相关用户登录信息缓存！";
                $this->logInstance->error($errMsg);
                throw new OAuthClientException($errMsg,401);
            }
	        $this->logInstance->info(sprintf("从缓存中获取的refresh token:%s",$refreshToken));
            
            
            // 组装请求参数
            $requestData["refresh_token"] = $refreshToken;
            $requestData["scope"] = $this->oauthConfig["scopes"];
            $requestData["grant_type"] = "refresh_token";
            $yckjProvider = new YiChKeJiPostAuthOptionProvider($this->oauthConfig["clientId"],$this->oauthConfig["clientSecret"]);
            $this->provider->setOptionProvider($yckjProvider);
            $logData["Request Options"] = $yckjProvider->getAccessTokenOptions(GenericProvider::METHOD_POST,$requestData);

            // 发送请求获取新的accessToken
            $accessToken = $this->provider->getAccessToken("refresh_token", $requestData);
            if(!$accessToken || !($accessToken instanceof AccessToken)){
                $logData["Error"] = sprintf("刷新access_token失败！查询获取Refresh Token日志！获取详细信息！");
                $logData["Error Data"] = mb_strcut((string)$accessToken,0,20)."...";
                $this->logInstance->error($logData);
                throw new OAuthClientException($logData["Error"],500);
            }

            // 删除已经存储的RefreshToken
            $this->deleteStoreRefreshToken($accessTokenCacheKey);
            // 删除已经存储的AccessToken
            $this->deleteStoreAccessToken($accessTokenCacheKey);
	        // 删除用户信息缓存
	        $this->deleteStoreUserDetail($accessTokenCacheKey);
	        // 更新缓存中的AccessToken数据
            $this->storeAccessToken($accessTokenCacheKey,$accessToken);
            

            $logData["Request Refresh Access Token Result"] = (array)$accessToken->jsonSerialize();
            $this->logInstance->write($logData);
            return $accessToken;
        } catch (IdentityProviderException $e) {
            $errMsg = implode(",",array_values($e->getResponseBody()));
            $errMsg = sprintf("刷新access_token失败！%s",$errMsg);
            $logData["Error"] = $errMsg;
            $this->logInstance->write($logData);
            throw new OAuthClientException($errMsg,500);
        } catch (CacheManagerException $e) {
            $this->logInstance->error($e->getMessage());
            throw new OAuthClientException($e->getMessage(),$e->getCode());
        }
    }
	
	/**
	 * 登出SSO系统
	 *
	 * @param string $accessTokenCacheKey
	 * @param bool   $isNotifySSOServer 是否通知SSO服务，true为通知，false为不通知；
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return bool
	 */
    public function logout(string $accessTokenCacheKey,bool $isNotifySSOServer = false){
        try {
            $result = [];
            $logData = [];
            // 获取缓存中的AccessToken
	        $accessToken = $this->getStoreAccessToken($accessTokenCacheKey);
            
            
            // 删除系统中相关用户缓存信息
            array_push(
                $result,
                $this->deleteStoreUserDetail($accessTokenCacheKey),
                $this->deleteStorePermission($accessTokenCacheKey),
                $this->deleteStoreRefreshToken($accessTokenCacheKey),
                $this->deleteStoreAccessToken($accessTokenCacheKey)
            );
            // 发送远程请求通知
            if($isNotifySSOServer){
                $header[HttpHeader::AUTHORIZATION] = sprintf("Bearer %s",$accessToken->getToken());
                $header[HttpHeader::CONTENT_TYPE] = MediaType::APPLICATION_FORM_URLENCODED_VALUE;
                $header[HttpHeader::ACCEPT] = MediaType::APPLICATION_JSON_UTF8_VALUE;
                $logoutUrl = $this->oauthConfig["logoutSSO"];
                // 请求数据
                $requestData = [];
                $requestDataStr = "";
                foreach ($requestData as $key=>$requestDatum) {
                    $requestDataStr .= sprintf("%s=%s&",$key,$requestDatum);
                }
                $requestDataStr = rtrim($requestDataStr,"&");

                $httpClient = new Client();
                $options["headers"] = $header;
                $options["body"] = $requestDataStr;
                $options["version"] = '1.1';
                $response = $httpClient->request("POST",$logoutUrl,$options);
                $logData["SSO Logout Url"] = $logoutUrl;
                $logData["SSO Logout Header"] = $header;
                $logData["SSO Logout Data"] = $requestData;
                $logData["SSO Logout State Response"] = $response->getBody()->getContents();
                $logData["SSO Logout State Code"] = $response->getStatusCode();
                if($response->getStatusCode() >= 200 && $response->getStatusCode() <= 299){
                    array_push($result,true);
                }else{
                    array_push($result,false);
                }
            }
            $this->logInstance->write($logData);
            return in_array(true,$result);
        } catch (OAuthClientException $e) {
            $logData["Error"] = sprintf("登出失败！删除用户信息错误！%s",$e->getMessage());
            $this->logInstance->write($logData);
            throw $e;
        }
    }

    // ==================================================================================== //
    // ============================== stateCode Cache相关操作 ============================== //
    // ==================================================================================== //
    /**
     * 获取stateCodeKey值
     *
     * @param string $stateCode
     * @return string
     */
    private function getStateCodeKey(string $stateCode){
        return sprintf(self::cache_state_tag.":%s",$stateCode);
    }
	
	/**
	 * 缓存 StateCode，StateCode 的过期时间600s 10分钟
	 *
	 * @param string $cacheKey
	 * @param string $stateCode
	 *
	 * @throws \OAuth2\exception\CacheManagerException
	 * @return mixed
	 */
    private function storeStateCode(string $cacheKey,string $stateCode){
        $stateCodeCacheKey = $this->getStateCodeKey($cacheKey);
        // 缓存state Code 过期时间600s；
	    return $this->cacheManager->setCacheData($stateCodeCacheKey,$stateCode,600);
    }
	
	/**
	 * 获取stateCode，成功获取后，缓存中将删除 StateCode
	 * @param string $cacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return mixed
	 */
    private function getStateCode(string $cacheKey){
	    $stateCodeCacheKey = $this->getStateCodeKey($cacheKey);
	    try {
		     $stateCode = $this->cacheManager->getCacheData($stateCodeCacheKey);
		     // 如果存在则删除
		     if($stateCode){
		        $this->cacheManager->deleteCacheData($stateCodeCacheKey);
		     }
		     return $stateCode;
	    } catch (CacheManagerException $e) {
	    	throw new OAuthClientException($e->getMessage(),$e->getCode(),$e);
	    }
    }
	
	// ==================================================================================== //
	// ============================= Permission Cache相关操作 ============================== //
	// ==================================================================================== //
	/**
	 * 生成缓存 Permission Key值
	 * @param string $cacheKey
	 *
	 * @return string
	 */
	private function getStorePermissionKey(string $cacheKey):string {
		$permissionKey = sprintf(self::cache_user_permission_tag.":%s",$cacheKey);
		$this->logInstance->info(sprintf("生成缓存Permission键为：%s",$permissionKey));
		return $permissionKey;
	}
	
	/**
	 * 缓存权限数据
	 * @param string $accessTokenCacheKey
	 * @param array  $permission
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return mixed
	 */
	private function storePermission(string $accessTokenCacheKey,array $permission){
		$accessTokenCacheKeyVal = $this->getStoreAccessTokenKey($accessTokenCacheKey);
		// 获取AccessToken的有效期
		$accessToken = $this->getStoreAccessToken($accessTokenCacheKeyVal);
		// 生成缓存权限信息键值
		$permissionCacheKey = $this->getStorePermissionKey($accessTokenCacheKey);
		// 缓存数据
		try {
			return $this->cacheManager->setCacheData($permissionCacheKey, $permission, ((int)$accessToken->getExpires() - time()));
		} catch (CacheManagerException $e) {
			$msg = "缓存permission【key=>".$permissionCacheKey."】失败！".$e->getMessage();
			$this->logInstance->error($msg);
			throw new OAuthClientException($msg,$e->getCode());
		}
	}
	
	/**
	 * 获取权限数据
	 *
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return array
	 */
	public function getStorePermission(string $accessTokenCacheKey):array {
		// 生成缓存权限信息键值
		$permissionCacheKey = $this->getStorePermissionKey($accessTokenCacheKey);
		// 获取缓存数据
		try {
			return $this->cacheManager->getCacheData($accessTokenCacheKey);
		} catch (CacheManagerException $e) {
			$err = "从缓存中获取permission【key=>".$permissionCacheKey."】失败！".$e->getMessage();
			$this->logInstance->error($err);
			throw new OAuthClientException($err,$e->getCode());
		}
	}
	
	/**
	 * 删除缓存权限数据
	 *
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return bool
	 */
	public function deleteStorePermission(string $accessTokenCacheKey){
		$permissionCacheKey = $this->getStorePermissionKey($accessTokenCacheKey);
		try {
			return $this->cacheManager
				->deleteCacheData($permissionCacheKey);
		} catch (CacheManagerException $e) {
			$err = "从缓存中删除permission【key=>".$permissionCacheKey."】失败！".$e->getMessage();
			$this->logInstance->error($err);
			throw new OAuthClientException($e->getMessage(),$e->getCode());
		}
	}
	
	/**
	 * 判断是否存在权限数据
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return bool
	 */
	public function hasStorePermission(string $accessTokenCacheKey){
		$permissionCacheKey = $this->getStorePermissionKey($accessTokenCacheKey);
		try {
			return $this->cacheManager->has($permissionCacheKey);
		} catch (CacheManagerException $e) {
			$err = "从缓存中判断是否存在permission【key=>".$permissionCacheKey."】失败！".$e->getMessage();
			$this->logInstance->error($err);
			throw new OAuthClientException($e->getMessage(),$e->getCode());
		}
	}
	
	// ==================================================================================== //
    // ============================ Refresh Token Cache相关操作 ============================ //
    // ==================================================================================== //
	/**
	 * 生成 refresh token 缓存Key值
	 *
	 * @param string $cacheKey 缓存键
	 *
	 * @return string
	 */
    private function getStoreRefreshTokenKey(string $cacheKey):string {
	    $refreshTokenKey = sprintf(self::cache_refresh_token_tag.":%s",$cacheKey);
	    $this->logInstance->info(sprintf("生成缓存RefreshToken键为：%s",$refreshTokenKey));
        return $refreshTokenKey;
    }
	
	/**
	 * 存储 refresh token to Cache
	 *
	 * @param string      $cacheKey 缓存键名
	 * @param AccessToken $accessToken
	 *
	 * @throws \OAuth2\exception\CacheManagerException
	 * @return mixed|string
	 */
    private function storeRefreshToken(string $cacheKey,AccessToken $accessToken) {
        // 存储refresh token，判断access token中是否存在refresh token
        // 如果存在则存储，不存在则不存储
        $refreshToken = $accessToken->getRefreshToken();
        if(!empty($refreshToken) && is_string($refreshToken) && strlen($refreshToken)>0){
            $refreshTokenKey = $this->getStoreRefreshTokenKey($cacheKey);
            // 存储
	        return $this->cacheManager->setCacheData(
	        	$refreshTokenKey,
		        $accessToken->getRefreshToken(),
	            // 比accessToken的过期时间长 1800 秒，延长30分钟后过期。
				$accessToken->getExpires() - time() + 1800
	        );
        }else{
            return true;
        }
    }
	
	/**
	 * 根据accessToken 获取 refresh token
	 *
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return mixed
	 */
    public function getStoreRefreshToken(string $accessTokenCacheKey) {
    	// 获取缓存refreshToken的键
        $refreshTokenKey = $this->getStoreRefreshTokenKey($accessTokenCacheKey);
        try {
            return $this->cacheManager->getCacheData($refreshTokenKey);
        } catch (CacheManagerException $e) {
	        $msg = "从缓存中获取refreshToken【key=>".$accessTokenCacheKey."】失败！".$e->getMessage();
	        $this->logInstance->error($msg);
	        throw new OAuthClientException($msg,500);
        }
    }
    
	/**
	 * 删除 refresh token
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return bool
	 */
    public function deleteStoreRefreshToken(string $accessTokenCacheKey){
        $refreshTokenKey = $this->getStoreRefreshTokenKey($accessTokenCacheKey);
        try {
            return $this->cacheManager->deleteCacheData($accessTokenCacheKey);
        } catch (CacheManagerException $e) {
	        $errMsg = "从缓存中删除refreshToken【key=>".$refreshTokenKey."】失败！".$e->getMessage();
	        $this->logInstance->error($errMsg);
	        throw new OAuthClientException($errMsg,500);
        }
    }

    // ==================================================================================== //
    // ============================ Access Token Cache相关操作 ============================= //
    // ==================================================================================== //
    /**
     * 生成存储或获取 accessToken Key 值
     * @param string $accessTokenStr
     * @return string
     */
    private function getStoreAccessTokenKey(string $accessTokenStr):string {
    	$accessTokenCacheKey =sprintf(self::cache_access_token_tag.":%s",$accessTokenStr);
	    $this->logInstance->info(sprintf("生成缓存AccessToken键为：%s",$accessTokenCacheKey));
        return $accessTokenCacheKey;
    }
	
	/**
	 * 存储用户accessToken to cache
	 *
	 * @param string                                  $cacheKey    缓存键
	 * @param \League\OAuth2\Client\Token\AccessToken $accessToken 缓存值
	 *
	 * @throws \OAuth2\exception\CacheManagerException
	 * @return bool
	 */
    private function storeAccessToken(string $cacheKey,AccessToken $accessToken):bool {
	    /**
	     * 第一步 存储accessToken
	     */
    	// 获取缓存键
        $accessTokenKey = $this->getStoreAccessTokenKey($cacheKey);
		$accessTokenRes = $this->cacheManager
			->setCacheData(
				$accessTokenKey,
				json_encode($accessToken->jsonSerialize(),JSON_UNESCAPED_UNICODE),
				(int)$accessToken->getExpires()-time()
			);
	    $accessTokenRes = $accessTokenRes instanceof $accessToken? true:false;
	
	    /**
	     * 第二步 单独存储 refresh Token
	     */
        // 如果AccessToken中存在refreshToken则存储refreshToken,
	    if($accessToken->getRefreshToken()){
		    $refreshTokenRes = $this->storeRefreshToken($cacheKey,$accessToken);
	    }else{
		    $refreshTokenRes = true;
	    }
	    return $accessTokenRes && $refreshTokenRes ? true:false;
    }
	
	/**
	 * 获取用户 accessToken from cache
	 *
	 * @param string $cacheAccessTokenKey accessToken缓存键
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return AccessToken
	 */
    public function getStoreAccessToken(string $cacheAccessTokenKey):AccessToken {
        $key = $this->getStoreAccessTokenKey($cacheAccessTokenKey);
        try {
            $accessTokenJson = $this->cacheManager->getCacheData($key);
            if(empty($accessTokenJson) || !$accessTokenJson){
                $msg = "缓存中不存在accessToken[".$cacheAccessTokenKey."]";
                $this->logInstance->error($msg);
                throw new OAuthClientException($msg,401);
            }
            $accessToken = (array)json_decode($accessTokenJson,true);
            if(!$accessToken){
	            $msg = "解析accessToken[".$cacheAccessTokenKey."]失败！存储至缓存中的token非json格式！";
                $this->logInstance->error($msg);
                throw new OAuthClientException($msg,500);
            }
            // 再判断缓存是否过期
            $accessTokenObj = new AccessToken($accessToken);
            if(time() > $accessTokenObj->getExpires()){
	            $msg = "accessToken[".$cacheAccessTokenKey."]已过期！重新获取access token(refresh_token)！";
                $this->logInstance->error($msg);
                throw new OAuthClientException($msg,400);
            }
            return $accessTokenObj;
        } catch (CacheManagerException $e) {
        	$msg =  "从缓存中获取accessToken【key=>".$key."】失败！".$e->getMessage();
	        $this->logInstance->error($msg);
	        throw new OAuthClientException($msg,500);
        }
    }
    
	/**
	 * 删除 accessToken from cache
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return bool
	 */
    public function deleteStoreAccessToken(string $accessTokenCacheKey){
        $key = $this->getStoreAccessTokenKey($accessTokenCacheKey);
        try {
            return $this->cacheManager->deleteCacheData($key);
        } catch (CacheManagerException $e) {
            $logData["Error"] = "从缓存中删除AccessToken【accessToken=>".$accessTokenCacheKey."】失败！".$e->getMessage();
            $this->logInstance->error($logData);
            throw new OAuthClientException($logData["Error"],500);
        }
    }

    // ==================================================================================== //
    // ============================= User Detail Cache相关操作 ============================= //
    // ==================================================================================== //
	/**
	 * 生成存储或获取userDetail Key 值
	 *
	 * @param string $accessTokenCacheKey
	 *
	 * @return string
	 */
    private function getStoreUserDetailKey(string $accessTokenCacheKey): string {
    	$userDetailKey = sprintf(self::cache_user_detail_tag.":%s",$accessTokenCacheKey);
	    $this->logInstance->info(sprintf("生成缓存用户信息的键：%s",$userDetailKey));
        return $userDetailKey;
    }
	
	/**
	 * 存储用户信息 to cache
	 *
	 * @param string               $accessTokenCacheKey     accessToken缓存键
	 * @param GenericResourceOwner $userDetail              用户信息对象
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return mixed
	 */
    private function storeUserDetail(string $accessTokenCacheKey,GenericResourceOwner $userDetail){
        $userDetailKey = $this->getStoreUserDetailKey($accessTokenCacheKey);
        // 获取从缓存中获取AccessToken，目的在于获取AccessToken的过期时间
	    // 根据过期时间设置用户信息的过期时间
        $accessToken = $this->getStoreAccessToken($accessTokenCacheKey);
        // 强制转化
        $userDetailArr = (array) $userDetail->toArray();
        if(!($accessToken instanceof AccessToken) || empty($accessToken)){
            $msg = "缓存中无该accessToken[".$accessToken."]！导致无法缓存用户信息！";
            $this->logInstance->error($msg);
            throw new OAuthClientException($msg,401);
        }
        try {
	        // 存储用户信息
	        return $this->cacheManager
		        ->setCacheData(
			        $userDetailKey,
			        json_encode($userDetailArr, JSON_UNESCAPED_UNICODE),
			        (int)($accessToken->getExpires() - time()));
        }catch (CacheManagerException $exception){
	        $errMsg = "缓存accessToken[".$accessToken."]所对应的用户信息失败！";
            $this->logInstance->error($errMsg);
            throw new OAuthClientException($errMsg,500);
        }
    }
	
	/**
	 * 判断缓存中是否存在用户信息
	 *
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return bool
	 */
    public function hasStoreUserDetail(string $accessTokenCacheKey){
        $userDetailKey = $this->getStoreUserDetailKey($accessTokenCacheKey);
        try {
            return $this->cacheManager->has($userDetailKey);
        } catch (CacheManagerException $e) {
            $error = "获取缓存中CacheKey[".$accessTokenCacheKey."]中所对应的AccessToken[".$accessTokenCacheKey."]所对应的用户信息失败！从缓存中获取用户信息失败！请检查缓存配置！";
            $this->logInstance->error($error);
            throw new OAuthClientException($error,$e->getCode());
        }
    }
	
	/**
	 * 获取用户信息 from cache
	 *
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return array
	 */
    public function getStoreUserDetail(string $accessTokenCacheKey): array {
        $userDetailKey = $this->getStoreUserDetailKey($accessTokenCacheKey);
        try {
            $userDetailValue = $this->cacheManager->getCacheData($userDetailKey);

            $userDetail = json_decode($userDetailValue,true);
            if(is_array($userDetail) && !empty($userDetail)){
                return $userDetail;
            }else{
                return [];
            }
        } catch (CacheManagerException $e) {
            $err = "获取缓存accessToken[".$accessTokenCacheKey."]所对应的用户信息失败！从缓存中获取用户信息失败！请检查缓存配置！";
            $this->logInstance->error($err);
            throw new OAuthClientException($err,$e->getCode());
        }
    }
    
	/**
	 * 删除用户信息 from cache
	 * @param string $accessTokenCacheKey
	 *
	 * @throws \OAuth2\exception\OAuthClientException
	 * @return bool
	 */
    public function deleteStoreUserDetail(string $accessTokenCacheKey){
        $userDetailKey = $this->getStoreUserDetailKey($accessTokenCacheKey);
        try {
            return $this->cacheManager->deleteCacheData($userDetailKey);
        } catch (CacheManagerException $e) {
	        $logData["Error"] = "从缓存中删除用户信息【access_token=>".$accessTokenCacheKey."】失败！".$e->getMessage();
	        $this->logInstance->write($logData);
	        throw new OAuthClientException($logData["Error"],500);
        }
    }

    // ==================================================================================== //
    // ====================================== Getter ====================================== //
    // ==================================================================================== //
    /**
     * 获取OAuth配置
     * @return array
     */
    public function getOauthConfig(): array
    {
        return $this->oauthConfig;
    }

    /**
     * 获取缓存配置
     * @return array
     */
    public function getCacheConfig(): array
    {
        return $this->cacheConfig;
    }
    
    public function getLoggerPath(){
    	return $this->logInstance->getLogRootPath();
    }
}