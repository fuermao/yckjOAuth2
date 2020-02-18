<?php


namespace OAuth2;


use GuzzleHttp\Client;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use OAuth2\exception\OAuthClientAuthCodeNotExistException;
use OAuth2\exception\OAuthClientException;
use OAuth2\exception\OAuthClientInitializationException;
use OAuth2\library\constant\HttpHeader;
use OAuth2\library\constant\MediaType;
use OAuth2\library\logger\Logger;
use OAuth2\library\YiChKeJiPostAuthOptionProvider;
use Psr\SimpleCache\InvalidArgumentException;
use think\CacheManager;
use think\facade\Cache;
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
     * @var Cache
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
    ];

    /**
     * 允许外部输入认证配置信息键名信息，以及内部 $oauthConfig 配置对应关系
     * 该变量的作用主要是检测外部输入键名是否匹配的
     * @var array
     */
    private static $oauthConfigInput = [
        // 认证服务根路径，如: http://test.xxxxxx.com 或 http://192.***.***.10:8091 端口形式
        "host"                      => "",
        // 在认证服务中注册本应用的clientId以及client_secret
        "client_id"                 => "clientId",
        "client_secret"             => "clientSecret",
        // 申明的权限内容
        "scope"                     => "scopes",
        // 授权码模式回调地址
        "authorize_redirect"        => "redirectUri",
        // 授权码获取地址
        "authorize_uri"             => "urlAuthorize,true",
        // token获取地址
        "access_token_uri"          => "urlAccessToken,true",
        // 获取用户信息
        "user_info_uri"             => "urlResourceOwnerDetails,true",
        // 登出SSO系统
        "logout_sso"                => "logoutSSO,true"
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
     * YiCKJOAuth2Client constructor.
     * @param array $cacheConfig
     */
    protected function __construct(array $cacheConfig=[]){
        // 初始化缓存策略
        $this->cacheManager = new CacheManager();
        // 设置默认缓存策略
        $this->cacheConfig["default"] = "file";
        // 设置默认文件缓存路径
        $this->cacheConfig["stores"]["file"]["path"] = dirname(__DIR__).DIRECTORY_SEPARATOR."runtime".DIRECTORY_SEPARATOR."cache".DIRECTORY_SEPARATOR;
        // 合并缓存配置
        $this->cacheConfig = array_merge($this->cacheConfig,$cacheConfig);
        $this->cacheManager->config($this->cacheConfig);
    }

    /**
     * 获取实例信息
     * @param array $oauthConfig OAuth配置参数
     * @param array $cacheConfig
     * @return YiCKJOAuth2Client
     */
    public final static function getInstance(array $oauthConfig,array $cacheConfig=[]): YiCKJOAuth2Client{
        if(static::$instance == null || empty(static::$instance)){
            static::$instance = new static($cacheConfig);
        }
        // 初始化信息
        static::$instance->init($oauthConfig);
        // 公有初始化信息(该函数可以继承)
        static::$instance->initialization();
        return static::$instance;
    }

    /**
     * 私有初始化配置
     * @param array $config
     * @throw OAuthClientInitializationException
     */
    private function init(array $config): void{
        $missKeysArr = array_diff_key(self::$oauthConfigInput,$config);
        // 判断必传参数是否为空
        if(!empty($missKeysArr) && is_array($missKeysArr)){
            $errMsg = sprintf("配置参数[%s]缺失，初始化失败！",implode(",",array_keys($missKeysArr)));
            throw new OAuthClientInitializationException($errMsg,500);
        }
        // 判断必传参数中是否存在空值
        if(in_array("",$config,true) || in_array(null,$config,true)){
            $valEmptyKey = array_search("",$config,true)?array_search("",$config,true):array_search(null,$config,true);
            $errMsg = sprintf("配置中[%s]值为空，初始化失败！",$valEmptyKey);
            throw new OAuthClientInitializationException($errMsg,500);
        }
        $arr = array_flip(self::$oauthConfigInput);
        // 如果$config不为空，则合并两个数组(中间可能存在不会使用的配置值)
        foreach ($arr as $key=>$item) {
            if(empty($key)){
                continue;
            }
            if(preg_match_all("/^([a-z]*)([\\,]true)$/i",$key)){
                list($key,$res) = explode(",",$key);
                if((boolean)$res){
                    $this->oauthConfig[$key] = $config["host"].$config[$item];
                }
            }else{
                $this->oauthConfig[$key] = $config[$item];
            }
        }
        $this->provider = new GenericProvider($this->oauthConfig);
    }

    /**
     * 公有初始化配置
     */
    protected function initialization(): void {
        // 初始化日志实例 两个条件：日志实例为空或者null 或者日志根路径与当前日志实例根路径不同，则初始化日志实例
        $this->logInstance = Logger::getInstance(self::$logFileName);
    }

    /**
     * 授权码模式获取授权码
     *
     * @throws OAuthClientException
     */
    public function authorizationCode()
    {
        // 获取认证服完整地址
        $getCodeUrl = $this->provider->getAuthorizationUrl();
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
        // 将stateStr存储与缓存中
        $this->storeStateCode($statStr);
        // 导向认证服务器
        header(sprintf("%s:%s",HttpHeader::JAVASCRIPT_AJAX,"XMLHttpRequest"));
        header("Location: ".$getCodeUrl);
        // 跳转后退出程序
        exit();
    }

    /**
     * 授权码模式通过 auth_code 交换 access_token
     * @return AccessToken
     * @throws OAuthClientAuthCodeNotExistException
     * @throws OAuthClientException
     * @throws \throwable
     */
    public function getAccessToken(): AccessToken {
        $logData["OAuth stage"]="授权码交换令牌阶段【access_token】";
        // 从GET传参中获取参数信息
        // 授权码
        $authCode = array_key_exists("code",$_GET)?htmlspecialchars(trim($_GET["code"])):"";
        // 状态码
        $stateStr = array_key_exists("state",$_GET)?htmlspecialchars(trim($_GET["state"])):"";
        if(empty($authCode) || empty($stateStr)){
            $logData["Error"] = "授权码(code)或状态码(state)缺失！";
            $this->logInstance->write($logData);
            throw new OAuthClientException("授权码(code)或状态码(state)缺失！",401);
        }
        // 判断缓存中是否存在state字符串
        try {
            $stateExistRes = $this->getStoreStateCode($stateStr);

            if(empty($stateExistRes)){
                $logData["Error"] = "状态码（state【".$stateStr."】）不存在或不匹配";
                $this->logInstance->write($logData);
                throw new OAuthClientAuthCodeNotExistException("状态码不存在或不匹配！",401);
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
                $logData["Error"] = "获取access_token失败！";
                $logData["Error Data"] = (string)$accessToken;
                $this->logInstance->write($logData);
                throw new OAuthClientException("获取access_token失败！",401);
            }
            // 使用thinkphp的缓存策略
            $logData["Access Token Result"] = "成功获取Token";
            $logData["Access Token"] = (array)$accessToken->jsonSerialize();
            $logData["Refresh Access Token"] = $accessToken->getRefreshToken();

            // 将token信息存储起来
            if($this->storeAccessToken($accessToken)){
                $logData["Cache Access Token Result"] = "存储accessToken成功！";
            }else{
                $logData["Cache Access Token Result"] = "存储accessToken失败！";
            }
            $this->logInstance->write($logData);
            return $accessToken;
        } catch (IdentityProviderException $e) {
            $exceptionMsg = "";
            if(is_array($e->getResponseBody())){
                $exceptionMsg = implode(",",array_values($e->getResponseBody()));
            }else{
                $exceptionMsg = $e->getResponseBody();
            }
            $errMsg = sprintf("获取access_token失败！%s",$exceptionMsg);
            $logData["Error"] = $errMsg;
            $this->logInstance->write($logData);
            throw new OAuthClientException($errMsg,500);
        } catch (OAuthClientAuthCodeNotExistException $e){
            $exceptionMsg = $e->getMessage();
            throw new OAuthClientException($exceptionMsg,$e->getCode());
        }
    }

    /**
     * 获取当前授权用户信息
     *
     * @param string $accessTokenStr
     * @return array
     * @throws OAuthClientException
     */
    public function getResourceOwnerDetail(string $accessTokenStr):array {
        $logData["OAuth stage"]="获取用户信息阶段【user_detail】";
        // 尝试从缓存中获取
        if($this->hasStoreUserDetail($accessTokenStr)){
            $userInfo = $this->getStoreUserDetail($accessTokenStr);
            $logData["Get User Info From Cache"] = "true";
            $logData["User Info"] = $userInfo;
            $this->logInstance->write($logData);
            return $userInfo;
        }else{
            try {
                // 获取accessToken
                $accessToken = $this->getStoreAccessToken($accessTokenStr);
                // 设置参数
                $this->provider->setOptionProvider(new YiChKeJiPostAuthOptionProvider($this->oauthConfig["clientId"],$this->oauthConfig["clientSecret"]));
                // 获取用户信息
                $userInfo = $this->provider->getResourceOwner($accessToken);
                if(!($userInfo instanceof GenericResourceOwner) || !$userInfo){
                    $errMsg = "获取用户信息失败！";
                    $logData["Error"] = $errMsg;
                    $this->logInstance->write($logData);
                    throw new OAuthClientException($errMsg,500);
                }
                // 将用户信息写入缓存中
                $this->storeUserDetail($accessToken->getToken(),$userInfo);
                // 将完整的解析
                $logData["User Info"] = (array)$userInfo->toArray();
                $this->logInstance->write($logData);
                return $userInfo->toArray();
            } catch (UnexpectedValueException $exception){
                $logData["Error"] = sprintf("获取用户信息失败，认证服响应非json格式，导致无法解析！%s",$exception->getMessage());
                // 获取用户信息失败
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],500);
            } catch (IdentityProviderException $exception){
                $errorBody = implode(",",array_values($exception->getResponseBody()));
                $logData["Error"] = sprintf("获取用户信息失败！%s！",$errorBody);
                // 获取用户信息失败
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],401);
            }
        }

    }

    /**
     * 更新 access token
     *
     * @param string $accessTokenStr 失效access Token
     * @return AccessToken
     * @throws OAuthClientException
     */
    public function refreshAccessToken(string $accessTokenStr):AccessToken{
        $logData["OAuth stage"]="刷新令牌阶段【refresh_access_token】";
        try {
            $refreshToken = $this->getStoreRefreshToken($accessTokenStr);
            if(empty($refreshToken) || !$refreshToken || $refreshToken == null){
                $logData["Error"] = "access token 无法获取refresh token！请核实Oauth Client是否具有获取refresh token权限！其次联系管理员清除相关用户登录信息缓存！";
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],401);
            }

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
                $logData["Error Data"] = (string)$accessToken;
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],500);
            }

            // 更新缓存中的数据
            $this->deleteStoreRefreshToken($accessTokenStr);
            $this->deleteStoreAccessToken($accessTokenStr);
            $this->storeAccessToken($accessToken);
            // 删除用户信息
            $this->deleteStoreUserDetail($accessTokenStr);

            $logData["Request Refresh Access Token Result"] = (array)$accessToken->jsonSerialize();
            $this->logInstance->write($logData);
            return $accessToken;
        } catch (IdentityProviderException $e) {
            $errMsg = implode(",",array_values($e->getResponseBody()));
            $errMsg = sprintf("刷新access_token失败！%s",$errMsg);
            $logData["Error"] = $errMsg;
            $this->logInstance->write($logData);
            throw new OAuthClientException($errMsg,500);
        }
    }

    /**
     * 登出SSO系统
     *
     * @param string $accessTokenStr
     * @return bool
     * @throws OAuthClientException
     */
    /**
     * 登出SSO系统
     *
     * @param string $accessTokenStr access token令牌
     * @param bool $isNotifySSOServer 是否通知SSO服务，true为通知，false为不通知；
     * @return bool
     * @throws OAuthClientException
     */
    public function logout(string $accessTokenStr,bool $isNotifySSOServer = false){
        try {
            $result = [];
            $logData = [];
            // 删除系统中相关用户缓存信息
            array_push(
                $result,
                $this->cacheManager->delete($this->getStoreUserDetailKey($accessTokenStr)),
                $this->cacheManager->delete($this->getStoreRefreshTokenKey($accessTokenStr)),
                $this->cacheManager->delete($this->getStoreAccessTokenKey($accessTokenStr))
            );
            // 发送远程请求通知
            if($isNotifySSOServer){
                $header[HttpHeader::AUTHORIZATION] = sprintf("Bear %s",$accessTokenStr);
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
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = sprintf("登出失败！删除用户信息错误！%s",$e->getMessage());
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
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
     * 存储缓存中的stateCode的值
     *
     * @param string $stateCode
     * @return mixed
     * @throws OAuthClientException
     */
    private function storeStateCode(string $stateCode){
        // 获取键名
        $stateCodeKey = $this->getStateCodeKey($stateCode);
        try {
            // 并设置10分钟后过期
            return $this->cacheManager
                ->tag(self::cache_state_tag)
                // 设置过期时间
                ->remember($stateCodeKey, $stateCode, 600);
        } catch (\throwable $e) {
            $logData["Error"] = "存储stateCode失败！".$e->getMessage();
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "存储stateCode失败！".$e->getMessage();
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        }
    }

    /**
     * 获取缓存中的stateCode的值
     *
     * @param string $stateCode
     * @return string
     * @throws OAuthClientException
     */
    private function getStoreStateCode(string $stateCode): string {
        $stateCodeKey = $this->getStateCodeKey($stateCode);
        try {
            $stateCodeCache = $this->cacheManager
                ->get($stateCodeKey);
            // 并删除缓存中的stateCode，stateCode属于一次业务，所以获取后就需要删除
            // 暂时取消该代码
             $this->cacheManager->delete($stateCodeKey);
            return !empty($stateCodeCache)?$stateCodeCache:false;
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "获取stateCode失败！".$e->getMessage();
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        }
    }

    // ==================================================================================== //
    // ============================ Refresh Token Cache相关操作 ============================ //
    // ==================================================================================== //
    /**
     * 生成 refresh token 缓存Key值
     * @param string $accessTokenStr
     * @return string
     */
    private function getStoreRefreshTokenKey(string $accessTokenStr):string {
        return sprintf(self::cache_refresh_token_tag.":%s",$accessTokenStr);
    }

    /**
     * 存储 refresh token to Cache
     *
     * @param AccessToken $accessToken
     * @return mixed|string
     * @throws OAuthClientException
     */
    private function storeRefreshToken(AccessToken $accessToken){
        // 存储refresh token，判断access token中是否存在refresh token
        // 如果存在则存储，不存在则不存储
        $refreshToken = $accessToken->getRefreshToken();
        if(!empty($refreshToken) && is_string($refreshToken) && strlen($refreshToken)>0){
            $refreshTokenKey = $this->getStoreRefreshTokenKey($accessToken->getToken());
            // 默认过期时间为 0
            try {
                return $this->cacheManager
                    ->tag(self::cache_refresh_token_tag)
                    // TODO：提供OAuth refresh Token 过期时间配置
                    // 比accessToken的过期时间长 1800 秒
                    ->remember($refreshTokenKey, $accessToken->getRefreshToken(),$accessToken->getExpires() - time() + 1800);
            } catch (\throwable $e) {
                $logData["Error"] = "存储RefreshToken失败！".$e->getMessage();
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],500);
            } catch (InvalidArgumentException $e) {
                $logData["Error"] = "存储RefreshToken失败！".$e->getMessage();
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],500);
            }
        }else{
            return false;
        }
    }

    /**
     * 根据accessToken 获取 refresh token
     *
     * @param string $accessTokenStr
     * @return mixed
     * @throws OAuthClientException
     */
    private function getStoreRefreshToken(string $accessTokenStr) {
        $refreshTokenKey = $this->getStoreRefreshTokenKey($accessTokenStr);
        try {
            return $this->cacheManager->get($refreshTokenKey);
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "从缓存中获取refreshToken【key=>".$accessTokenStr."】失败！".$e->getMessage();
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        }
    }

    /**
     * 删除 refresh token
     *
     * @param string $accessTokenStr
     * @throws OAuthClientException
     */
    private function deleteStoreRefreshToken(string $accessTokenStr){
        $refreshTokenKey = $this->getStoreRefreshTokenKey($accessTokenStr);
        try {
            $this->cacheManager->delete($refreshTokenKey);
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "从缓存中删除refreshToken【key=>".$accessTokenStr."】失败！".$e->getMessage();
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
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
        return sprintf(self::cache_access_token_tag.":%s",$accessTokenStr);
    }

    /**
     * 存储用户accessToken to cache
     *
     * @param AccessToken $accessToken
     * @return mixed
     * @throws OAuthClientException
     */
    private function storeAccessToken(AccessToken $accessToken){
        $accessTokenKey = $this->getStoreAccessTokenKey($accessToken->getToken());
        // 存储refreshToken
        $this->storeRefreshToken($accessToken);
        try {
            return $this->cacheManager
                ->tag(self::cache_access_token_tag)
                ->remember($accessTokenKey, json_encode((array)$accessToken->jsonSerialize()), (int)($accessToken->getExpires() - time()));
        } catch (\throwable $e) {
            $logData["Error"] = "存储accessToken失败！".$e->getMessage();
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "存储accessToken失败！".$e->getMessage();
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        }
    }

    /**
     * 获取用户 accessToken from cache
     *
     * @param string $accessTokenStr
     * @return AccessToken
     * @throws OAuthClientException
     */
    public function getStoreAccessToken(string $accessTokenStr):AccessToken {
        $key = $this->getStoreAccessTokenKey($accessTokenStr);
        $logData = [];
        try {
            $accessTokenJson = $this->cacheManager->get($key);
            if(empty($accessTokenJson) || !$accessTokenJson){
                $logData["Error"] = "缓存中不存在accessToken[".$accessTokenStr."]";
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],401);
            }
            $accessToken = (array)json_decode($accessTokenJson,true);
            if(!$accessToken){
                $logData["Error"] = "解析accessToken[".$accessTokenStr."]失败！存储至缓存中的token非json格式！";
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],500);
            }
            // 再判断缓存是否过期
            $accessTokenObj = new AccessToken($accessToken);
            if(time() > $accessTokenObj->getExpires()){
                $logData["Error"] = "accessToken[".$accessTokenStr."]已过期！重新获取access token(refresh_token)！";
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],400);
            }
            return $accessTokenObj;
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "从缓存中获取accessToken【key=>".$key."】失败！".$e->getMessage();
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        }
    }

    /**
     * 删除 accessToken from cache
     *
     * @param string $accessTokenStr
     * @throws OAuthClientException
     */
    private function deleteStoreAccessToken(string $accessTokenStr){
        $key = $this->getStoreAccessTokenKey($accessTokenStr);
        try {
            $this->cacheManager->delete($key);
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "从缓存中删除AccessToken【accessToken=>".$accessTokenStr."】失败！".$e->getMessage();
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        }
    }

    // ==================================================================================== //
    // ============================= User Detail Cache相关操作 ============================= //
    // ==================================================================================== //
    /**
     * 生成存储或获取userDetail Key 值
     *
     * @param string $accessTokenStr
     * @return string
     */
    private function getStoreUserDetailKey(string $accessTokenStr): string {
        return sprintf(self::cache_user_detail_tag.":%s",$accessTokenStr);
    }

    /**
     * 存储用户信息 to cache
     *
     * @param string $accessTokenStr
     * @param GenericResourceOwner $userDetail
     * @return mixed
     * @throws OAuthClientException
     */
    private function storeUserDetail(string $accessTokenStr,GenericResourceOwner $userDetail){
        $userDetailKey = $this->getStoreUserDetailKey($accessTokenStr);

        $accessToken = $this->getStoreAccessToken($accessTokenStr);
        // 强制转化
        $userDetailArr = (array) $userDetail->toArray();
        if(!($accessToken instanceof AccessToken) || empty($accessToken)){
            $logData["Error"] = "缓存中无该accessToken[".$accessToken."]！导致无法缓存用户信息！";
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],401);
        }
        try {
            // 存储用户信息
            return $this->cacheManager
                ->tag(self::cache_user_detail_tag)
                ->remember($userDetailKey,json_encode($userDetailArr),(int)($accessToken->getExpires() - time()));
        } catch (\throwable $e) {
            $logData["Error"] = "缓存accessToken[".$accessToken."]所对应的用户信息失败！";
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],401);
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "缓存accessToken[".$accessToken."]所对应的用户信息失败！";
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],401);
        }
    }

    /**
     * 判断缓存中是否存在用户信息
     *
     * @param string $accessTokenStr
     * @return bool
     * @throws OAuthClientException
     */
    private function hasStoreUserDetail(string $accessTokenStr){
        $userDetailKey = $this->getStoreUserDetailKey($accessTokenStr);
        try {
            return $this->cacheManager->has($userDetailKey);
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "获取缓存accessToken[".$accessTokenStr."]所对应的用户信息失败！从缓存中获取用户信息失败！请检查缓存配置！";
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        }
    }

    /**
     * 获取用户信息 from cache
     * @param string $accessTokenStr
     * @return array
     * @throws OAuthClientException
     */
    private function getStoreUserDetail(string $accessTokenStr): array {
        $userDetailKey = $this->getStoreUserDetailKey($accessTokenStr);
        try {
            $userDetailValue = $this->cacheManager->get($userDetailKey);

            $userDetail = json_decode($userDetailValue,true);
            if(is_array($userDetail) && !empty($userDetail)){
                return $userDetail;
            }else{
                $logData["Error"] = "获取缓存accessToken[".$accessTokenStr."]所对应的用户信息失败！用户尚未登录！";
                $this->logInstance->write($logData);
                throw new OAuthClientException($logData["Error"],401);
            }
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "获取缓存accessToken[".$accessTokenStr."]所对应的用户信息失败！从缓存中获取用户信息失败！请检查缓存配置！";
            $this->logInstance->write($logData);
            throw new OAuthClientException($logData["Error"],500);
        }
    }


    /**
     * 删除用户信息 from cache
     *
     * @param string $accessTokenStr
     * @throws OAuthClientException
     */
    private function deleteStoreUserDetail(string $accessTokenStr){
        $userDetailKey = $this->getStoreUserDetailKey($accessTokenStr);
        try {
            $this->cacheManager->delete($userDetailKey);
        } catch (InvalidArgumentException $e) {
            $logData["Error"] = "从缓存中删除用户信息【access_token=>".$accessTokenStr."】失败！".$e->getMessage();
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
}