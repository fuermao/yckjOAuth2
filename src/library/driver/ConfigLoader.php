<?php


namespace OAuth2\library\driver;


use OAuth2\exception\PathNotExistException;

class ConfigLoader
{
	/**
	 * @var \OAuth2\library\driver\ConfigLoader
	 */
	private static $instance;
	
	/**
	 * @var array 配置数组
	 */
	private $config = [];
	
	/**
	 * @var string 配置目录
	 */
	private $configPath = "";
	
	private function __construct($configPath)
	{
		$this->configPath = $configPath;
		$this->config = $this->loadConfPhpFile();
	}
	
	/**
	 * @param string $configPath    配置文件所在目录
	 *
	 * @throws \OAuth2\exception\PathNotExistException
	 * @return \OAuth2\library\driver\ConfigLoader
	 */
	public static function getInstance(string $configPath): ConfigLoader
	{
		// 校验配置路径
		if(!is_dir($configPath) || !file_exists($configPath) || !realpath($configPath) ){
			throw new PathNotExistException("配置路径不存在！");
		}
		// 实例化自己
		if(self::$instance == null || !(self::$instance instanceof ConfigLoader)){
			self::$instance = new self($configPath);
		}else if(self::$instance->configPath != $configPath){
			self::$instance = new self($configPath);
		}
		self::$instance->config = self::$instance->loadConfPhpFile();
		return self::$instance;
	}
	
	/**
	 * @return array 加载配置
	 */
	private function loadConfPhpFile():array {
		// 加载文件
		$dirResource = opendir($this->configPath);
		while(($fileName = readdir($dirResource)) !== false){
			if(preg_match_all("/^[\.]{1,2}$/",$fileName)){
				continue;
			}
			// 拼接文件完整路径
			$filePath = $this->configPath.$fileName;
			if(is_file($filePath) && file_exists($filePath)){
				list($configKey) = explode(".",$fileName);
				// 加载文件
				$conf[$configKey] = include($filePath);
			}
		}
		closedir($dirResource);
		return $conf;
	}
	
	/**
	 * 获取配置
	 * @param string $configKey 支持通过.获取多维数组值
	 *
	 * @return array|mixed|string
	 */
	public function get(string $configKey = ""){
		if(empty($configKey) || $configKey == null){
			return $this->config;
		}
		return $this->getValue($configKey,$this->config);
	}
	
	/**
	 * 给配置赋值
	 *
	 * @param string $configKey
	 * @param        $val
	 *
	 * @return bool
	 */
	public function set(string $configKey,$val):bool {
		if(empty($configKey) || $configKey == null){
			return false;
		}
		// TODO： 后面在写赋值的问题
	}
	
	/**
	 * 递归查询多维数组值
	 * @param string $key
	 * @param array  $arr
	 *
	 * @return mixed|string
	 */
	private function getValue(string $key,array $arr){
		$keyArr = explode(".",$key);
		// 去除空值
		$keyArr = array_filter($keyArr);
		// 直接返回值
		if(sizeof($arr) == 0){
			return "";
		}
		// 遍历取值
		while (($keyName = array_shift($keyArr)) != null){
			if(array_key_exists($keyName,$arr)){
				if(is_array($arr[$keyName]) && sizeof($arr[$keyName]) > 0 && sizeof($keyArr) > 0){
					return self::getValue(implode(".",$keyArr),$arr[$keyName]);
				}else{
					return $arr[$keyName];
				}
			}else{
				return "";
			}
		}
	}
}