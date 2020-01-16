<?php


namespace OAuth2;


use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use OAuth2\exception\OAuthClientAuthCodeNotExistException;
use OAuth2\exception\OAuthClientException;
use OAuth2\exception\OAuthClientInitializationException;
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
        // 授权码获取地址
        "authorize_uri"             => "urlAuthorize,true",
        // 授权码模式回调地址
        "authorize_redirect"        => "redirectUri",
        // token获取地址
        "access_token_uri"          => "urlAccessToken,true",
        // 获取用户信息
        "user_info_uri"             => "urlResourceOwnerDetails,true",
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
     * 缓存user detail（用户信息）标签名称
     */
    const cache_user_detail_tag = "yckj_user_detail";

    private static $logFileName = "yckj_auth_code";

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
            "Service States Code"=>$statStr
        ]);

        try {
            // 使用thinkphp的缓存策略，并设置state失效时间
            $this->cacheManager->tag(self::cache_state_tag)->remember(self::cache_state_tag.":".$statStr, $statStr, 36000);
            // 记录日志信息
            Logger::getInstance(static::$logFileName)->write($logData);
            // 导向认证服务器
            header("Location: ".$getCodeUrl);
        } catch (\throwable $e) {
            $errMsg = "缓存state【".$statStr."】失败！".$e->getMessage();
            $logData["Error"] = $errMsg;
            Logger::getInstance(static::$logFileName)->write($logData);
            throw new OAuthClientException("",500);
        } finally {
            // 跳转后退出程序
            exit();
        }


    }

    /**
     * 授权码模式获取access_token
     * @throws OAuthClientException
     * @throws OAuthClientAuthCodeNotExistException
     */
    public function getAccessToken(): AccessToken {
        $logData["OAuth stage"]="授权码交换令牌阶段【access_token】";
        // 从GET传参中获取参数信息
        // 授权码
        $authCode = array_key_exists("code",$_GET)?$_GET["code"]:"";
        // 状态码
        $stateStr = array_key_exists("state",$_GET)?$_GET["state"]:"";
        if(empty($authCode) || empty($stateStr)){
            $logData["Error"] = "授权码(code)或状态码(state)缺失！";
            Logger::getInstance(static::$logFileName)->write($logData);
            throw new OAuthClientException("授权码(code)或状态码(state)缺失！",401);
        }

        // 判断缓存中是否存在state字符串
        try {
            $stateExistRes = $this->cacheManager->has(self::cache_state_tag.":".$stateStr);
            if(!$stateExistRes){
                $logData["Error"] = "状态码（state【".$stateStr."】）不存在或不匹配";
                Logger::getInstance(static::$logFileName)->write($logData);
                throw new OAuthClientAuthCodeNotExistException("状态码不存在或不匹配！",401);
            }
            // 拼装请求
            // 获取授权码对象
            $providerOptions = new YiChKeJiPostAuthOptionProvider($this->oauthConfig["clientId"],$this->oauthConfig["clientSecret"]);
            // 设置请求头以及request body中必须的请求参数
            $this->provider->setOptionProvider($providerOptions);
            // 拼装请求参数数组
            $requestData["code"] = $_GET["code"];
            $requestData["scope"] = $this->oauthConfig["scopes"];

            // 日志参数
            $logData["Request Options"] = $providerOptions->getAccessTokenOptions(GenericProvider::METHOD_POST,$requestData);
            // 授权码
            $accessToken = $this->provider->getAccessToken("authorization_code",$requestData);
            // 判断是否成功获取 access_token
            if(!$accessToken || !($accessToken instanceof AccessToken)){
                $logData["Error"] = "获取access_token失败";
                $logData["Error Data"] = (string)$accessToken;
                Logger::getInstance(static::$logFileName)->write($logData);
                throw new OAuthClientException("获取access_token失败！",401);
            }
            // // 使用thinkphp的缓存策略
            $logData["Access Token"] = $accessToken->jsonSerialize();
            $logData["Access Token Result"] = "成功获取Token";
            // 将token信息存储起来
            $this->cacheManager
                ->tag(self::cache_access_token_tag)
                ->remember(self::cache_access_token_tag.":".$accessToken->getToken(),json_encode($accessToken->jsonSerialize()));
            return $accessToken;
        } catch (InvalidArgumentException $e) {
            $errMsg = sprintf("缓存读取(写入失败)失败！%s",$e->getMessage());
            $logData["Error"] = $errMsg;
            Logger::getInstance(static::$logFileName)->write($logData);
            throw new OAuthClientException("缓存读取失败！",500);
        } catch (IdentityProviderException $e) {
            $errMsg = sprintf("获取access_token失败！%s%s",$e->getMessage(),$e->getResponseBody());
            $logData["Error"] = $errMsg;
            Logger::getInstance(static::$logFileName)->write($logData);
            throw new OAuthClientException($errMsg,500);
        } finally {
            Logger::getInstance(static::$logFileName)->write($logData);
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
        try {
            if (!$this->cacheManager->has(self::cache_access_token_tag.":".$accessTokenStr)) {
                $errMsg = "获取登录失败！无有效access_token[".$accessTokenStr."]！";
                $logData["Error"] = $errMsg;
                Logger::getInstance("user_detail")->write($logData);
                throw new OAuthClientException($errMsg,401);
            }
            $accessTokenArr = (array)json_decode($this->cacheManager->get(self::cache_access_token_tag.":".$accessTokenStr));
            if(!$accessTokenArr || !is_array($accessTokenArr)){
                $errMsg = "解析缓存中access_token[".$accessTokenStr."]失败！";
                $logData["Error"] = $errMsg;
                Logger::getInstance("user_detail")->write($logData);
                throw new OAuthClientException($errMsg,500);
            }

            // 将token实例化
            $accessToken = new AccessToken($accessTokenArr);
            unset($accessTokenArr);

            // 设置参数
            $this->provider->setOptionProvider(new YiChKeJiPostAuthOptionProvider($this->oauthConfig["clientId"],$this->oauthConfig["clientSecret"]));
            // 获取用户信息
            $userInfo = $this->provider->getResourceOwner($accessToken);
            if(!($userInfo instanceof GenericResourceOwner) || !$userInfo){
                $errMsg = "获取用户信息失败！";
                $logData["Error"] = $errMsg;
                Logger::getInstance("user_detail")->write($logData);
                throw new OAuthClientException($errMsg,500);
            }
            // 解析为数组
            $userInfoArr = (array)$userInfo->toArray();
            // 将用户信息写入缓存中
            $this->cacheManager->tag(self::cache_user_detail_tag)->set(self::cache_user_detail_tag.":".$accessToken->getToken(),json_encode($userInfoArr));
            // 将完整的解析
            $logData["User Info"] = $userInfoArr;
            return $userInfo->toArray();
        } catch (InvalidArgumentException $e) {
            // 获取缓存失败
            Logger::getInstance("user_detail")->write(["Error"=>sprintf("读写缓存中数据失败！%s",$e->getMessage())]);
        } catch (UnexpectedValueException $exception){
            // 获取用户信息失败
            Logger::getInstance("user_detail")->write(["Error"=>sprintf("获取用户信息失败，所获取用户信息非json格式，导致无法解析！%s",$exception->getMessage())]);
        }finally {
            Logger::getInstance("user_detail")->write($logData);
        }
    }

    /**
     * 更新token
     *
     * @param string $accessToken
     * @throws OAuthClientException
     */
    public function refreshAccessToken(string $accessToken){
        $requestData["refresh_token"] = $accessToken;
        $logData["OAuth stage"]="获取用户信息阶段【refresh_access_token】";
        $this->provider->setOptionProvider(new YiChKeJiPostAuthOptionProvider($this->oauthConfig["clientId"],$this->oauthConfig["clientSecret"]));
        try {
            $accessToken = $this->provider->getAccessToken("refresh_token", $requestData);
        } catch (IdentityProviderException $e) {
            $body = $e->getResponseBody();
            $errMsg = implode(",",array_values($e->getResponseBody()));
            $errMsg = sprintf("刷新access_token失败！%s",$errMsg);
            $logData["Error"] = $errMsg;
            Logger::getInstance("refresh_access_token")->write($logData);
            throw new OAuthClientException($errMsg,500);
        }
    }

    /**
     * 存储或获取accessToken Key 值
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
     */
    private function storeAccessToken(AccessToken $accessToken){

    }



    /**
     * 获取用户accessToken from cache
     *
     * @param string $accessTokenStr
     * @throws OAuthClientException
     */
    private function getStoreAccessToken(string $accessTokenStr){
        $key = $this->getStoreAccessTokenKey($accessTokenStr);
        try {
            $this->cacheManager->get($key);
        } catch (InvalidArgumentException $e) {
            $errMsg = "获取";
            throw new OAuthClientException("");
        }
    }

    /**
     * 存储用户信息 to cache
     *
     * @param GenericResourceOwner $userDetail
     */
    private function storeUserDetail(GenericResourceOwner $userDetail){

    }

    /**
     * 获取用户accessToken from cache
     *
     * @param string $accessToken
     */
    private function getStoreUserDetail(string $accessToken){

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