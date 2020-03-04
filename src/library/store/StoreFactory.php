<?php


namespace OAuth2\library\store;


use OAuth2\exception\CacheManagerException;
use OAuth2\library\logger\Logger;
use Psr\SimpleCache\InvalidArgumentException;
use think\CacheManager;

class StoreFactory
{
	
	/**
	 * 文件分隔符常量
	 */
	const OAUTH2_DS         = DIRECTORY_SEPARATOR;
	
	/**
	 * 临时运行目录常量
	 */
	const TEMP_RUN_DIR      = "runtime";
	
	/**
	 * 临时缓存文件类型默认目录常量
	 */
	const FILE_CACHE_DIR    = "cache";
	
	/**
	 * 缓存默认前缀
	 */
	const CACHE_PREFIX      = "yic_oauth2";
	
	/**
	 * 缓存默认日志文件名称
	 */
	const CACHE_LOG_NAME = "CacheStore";
	
	/**
	 * @var array 缓存配置
	 */
	private $cacheConf = [
		// 默认缓存策略
		'default'	=>	'file',
		'stores'	=>	[
			// 文件类型缓存
			'file'	=>	[
				'type'   => 'File',
				// 缓存保存目录
				'path'   => "",
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
	
	/**
	 * @var \think\CacheManager 缓存管理实例
	 */
	private $cacheManager = null;
	
	/**
	 * @var string 组件根目录
	 */
	private $rootPath = "";
	
	/**
	 * @var string 默认缓存目录
	 */
	private $defaultCacheDir = "";
	
	/**
	 * @var Logger
	 */
	private $logger;
	
	/**
	 * @var \OAuth2\library\store\StoreFactory 工厂实例
	 */
	private static $instance;
	
	/**
	 * StoreFactory constructor.
	 */
	protected function __construct()
	{
		// 组件根目录
		$this->rootPath = realpath(dirname(dirname(dirname(__DIR__)))).self::OAUTH2_DS;
		// 缓存默认路径
		$this->defaultCacheDir = $this->rootPath.self::TEMP_RUN_DIR.self::OAUTH2_DS.self::FILE_CACHE_DIR.self::OAUTH2_DS;
		// ============================ 配置初始化 ============================ //
		// 设置默认缓存策略
		$this->cacheConf["default"] = "file";
		// 设置默认缓存文件存储路径
		$this->cacheConf["stores"]["file"]["path"] = $this->defaultCacheDir;
		// 设置默认缓存前缀
		$this->cacheConf["stores"]["file"]["prefix"] = self::CACHE_PREFIX;
		// 设置默认缓存有效期
		$this->cacheConf["stores"]["file"]["expire"] = 0;
		// 生成缓存实例
		$this->cacheManager = new CacheManager();
	}
	
	/**
	 * 单例模式获取工厂实例
	 *
	 * @param array  $cacheConfig   所传参数可参见 $this->cacheConfig 数组
	 * @param string $logDir        日志文件目录
	 *
	 * @return \OAuth2\library\store\StoreFactory
	 */
	public static function getInstance(array $cacheConfig=[],string $logDir=""):StoreFactory
	{
		// 判断是否实例化了自己
		self::$instance = (self::$instance == null || !(self::$instance instanceof StoreFactory ) )? new self() : self::$instance;
		// 初始化
		self::$instance->init($cacheConfig);
		return self::$instance;
	}
	
	/**
	 * 初始化工厂信息
	 *
	 * @param array  $cacheConfig   缓存配置
	 * @param string $logDir        日志文件目录
	 */
	private function init(array $cacheConfig = [],string $logDir=""): void{
		// ============================ 配置合并 ============================ //
		$this->cacheConf = array_merge($this->cacheConf,$cacheConfig);
		// 缓存实例配置信息
		$this->cacheManager->init($this->cacheConf);
		// 创建日志实例
		$this->logger = Logger::getInstance(self::CACHE_LOG_NAME,$logDir);
		// 其他的初始化信息，允许继承
		$this->initialization();
	}
	
	/**
	 * 初始化函数
	 */
	protected function initialization(): void{
	
	}
	
	/**
	 * 存储数据至缓存中
	 *
	 * @param string $cacheKeyName
	 * @param mixed  $data          存储数据
	 * @param int    $expiredTime   过期时间，无符号整数，0为永久有效缓存
	 *                              若不传则以缓存配置所设置过期为默认时间
	 *
	 * @throws \OAuth2\exception\CacheManagerException
	 * @return mixed 返回存储数据
	 */
	public function setCacheData(string $cacheKeyName,$data,int $expiredTime){
		
		try {
			return $this->cacheManager->remember($cacheKeyName, $data, $expiredTime);
		} catch (\throwable $e) {
			$errorMsg = "设置缓存数据失败！".$e->getMessage();
			$this->logger->fatal($errorMsg);
			throw new CacheManagerException($errorMsg,500,$e);
		} catch (InvalidArgumentException $e) {
			$errorMsg = "设置缓存数据不符合PSR-规范，缓存数据失败！".$e->getMessage();
			$this->logger->fatal($errorMsg);
			throw new CacheManagerException($errorMsg,500,$e);
		}
	}
	
	/**
	 * 获取缓存
	 *
	 * @param string $cacheKeyName      缓存键名
	 *
	 * @throws \OAuth2\exception\CacheManagerException
	 * @return mixed
	 */
	public function getCacheData(string $cacheKeyName){
		try {
			return $this->cacheManager->get($cacheKeyName);
		} catch (InvalidArgumentException $e) {
			$errorMsg = "获取缓存数据失败！".$e->getMessage();
			$this->logger->fatal($errorMsg);
			throw new CacheManagerException($errorMsg,500,$e);
		}
	}
	
	/**
	 * 删除指定键名缓存数据
	 * @param string $cacheKeyName
	 *
	 * @throws \OAuth2\exception\CacheManagerException
	 * @return bool
	 */
	public function deleteCacheData(string $cacheKeyName): bool {
		try {
			return $this->cacheManager->delete($cacheKeyName);
		} catch (InvalidArgumentException $e) {
			$errorMsg = "删除缓存数据失败！".$e->getMessage();
			$this->logger->warn($errorMsg);
			throw new CacheManagerException($errorMsg,500);
		}
	}
	
	/**
	 * 删除所有缓存数据
	 *
	 * @return bool
	 */
	public function clearAllCacheData(): bool{
		return $this->cacheManager->clear();
	}
	
	/*****************************************************************************/
	/* ============================ Setter & Getter ============================ */
	 /****************************************************************************/
	/**
	 * 设置缓存配置
	 * @param array $cacheConf
	 *
	 * @return \OAuth2\library\store\StoreFactory
	 */
	public function setCacheConf(array $cacheConf): StoreFactory
	{
		$this->cacheConf = array_merge($this->cacheConf,$cacheConf);
		$this->cacheManager->config($this->cacheConf);
		return $this;
	}
	
	/**
	 * 获取实例中缓存配置
	 * @return array
	 */
	public function getCacheConf(): array
	{
		return $this->cacheConf;
	}
	
	/**
	 * 根据键名判断是否存在
	 * @param string $cacheKey
	 *
	 * @throws \OAuth2\exception\CacheManagerException
	 * @return bool
	 */
	public function has(string $cacheKey):bool
	{
		try {
			return $this->cacheManager->has($cacheKey);
		} catch (InvalidArgumentException $e) {
			throw new CacheManagerException($e->getMessage(),500);
		}
	}
}