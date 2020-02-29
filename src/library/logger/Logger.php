<?php


namespace OAuth2\library\logger;


use OAuth2\library\constant\LogType;

final class Logger
{
	/**
	 * 日志文件后缀
	 */
	const LOGFILE_SUFFIX = ".log";
	
	/**
	 * 日志文件分隔符
	 */
	const LOG_DIR_DS = DIRECTORY_SEPARATOR;
	
	/**
	 * @var \OAuth2\library\logger\Logger 日志实例
	 */
    private static $instance;

    /**
     * 日志根目录
     * @var string
     */
    private $logRootPath;

    /**
     * 日志文件名称
     * @var string
     */
    private $logFileName;

    /**
     * 完整日志文件绝对路径
     * @var string
     */
    private $fullLogFileRealPath;

    protected function __construct()
    {
        // 初始化日志根目录
        $this->logRootPath = dirname(dirname(dirname(__DIR__))).self::LOG_DIR_DS."runtime".self::LOG_DIR_DS."log".self::LOG_DIR_DS;
        // 默认日志文件文件名称
	    $this->logFileName = date("d",time());
    }

    /**
     * 初始化操作
     */
    private function init():void {
    	// 去除末尾多余文件分隔符
    	$this->logRootPath = rtrim($this->logRootPath,self::LOG_DIR_DS);
	    // 日志目录路径补充年份划分日志目录
	    $this->logRootPath.= sprintf(self::LOG_DIR_DS."%s".self::LOG_DIR_DS."%s".self::LOG_DIR_DS,
		    date("Y",time()),
		    date("m",time())
	    );
	    // 创建日志目录
        if(!is_dir(self::$instance->logRootPath)){
            mkdir(self::$instance->logRootPath,0766,true);
        }
        // 完善日志文件路径
	    if($this->logFileName == date("d",time())){
		    $this->fullLogFileRealPath = $this->logRootPath.$this->logFileName.self::LOGFILE_SUFFIX;
	    }else{
		    $this->fullLogFileRealPath = $this->logRootPath.$this->logFileName."-".date("d",time()).self::LOGFILE_SUFFIX;
	    }
	    // 创建日志文件
        if(!file_exists($this->fullLogFileRealPath)){
            file_put_contents($this->fullLogFileRealPath,"");
        }
    }
	
	/**
	 * 获取实例化，单例模式
	 *
	 * @param string $logFileName   不包含后缀
	 * @param string $logDir        日志目录，不传则按照默认目录执行
	 *
	 * @return Logger
	 */
    public static function getInstance(string $logFileName,string $logDir = ""): Logger{
        // 判断是否存在自己的实例
    	if(self::$instance == null){
            self::$instance = new self();
        }
        // 覆盖默认日志目录
        self::$instance->logRootPath = !empty($logDir) && $logDir != ""?$logDir:self::$instance->logRootPath;
    	// 覆盖默认日志文件名称
	    self::$instance->logFileName = !empty($logFileName) && $logFileName != ""?$logFileName:self::$instance->logFileName;
	    self::$instance->init();
	    
        return self::$instance;
    }

    /**
     * 将日志数据写入日志中当前请求数据
     * @param array $data
     */
    public function write(array $data=[])
    {
        $logData = [];
        $logData["Date"]                    = date("Y-m-d H:i:s",time());
        $logData["Date Timestamp"]          = microtime(true);
        // 请求域名
        $logData["Request Http Host"]       = $_SERVER["HTTP_HOST"];
        // 请求端口
        $logData["Request Port"]            = $_SERVER["SERVER_PORT"];
        $logData["Request Ip Address"]      = $_SERVER["REMOTE_ADDR"];
        $logData["Request Document Uri"]    = $_SERVER["DOCUMENT_URI"];
        $logData["Request Request Uri"]     = $_SERVER["REQUEST_URI"];
        $logData["Request Method"]          = $_SERVER["REQUEST_METHOD"];
        // 获取请求头信息
        $requestHeader = apache_request_headers();
        foreach ($requestHeader as $key=>$item) {
            $logData["Request Header ".$key] = $item;
        }
        // 请求参数
        $logData["Request Data(POST)"]      = $_POST;
        $logData["Request Data(GET)"]       = $_GET;
        $logData["Request Data(ALL)"]       = $_REQUEST;
        // 合并日志数据
        $logData = array_merge($logData,$data);
		// 拼装日志字符串
        $logStr = "";
        $logStr.= "=========================== Log Start ===========================".PHP_EOL;
        foreach ($logData as $key=>$logDatum) {
            if(is_array($logDatum)){
                $logDatum = json_encode($logDatum);
            }
            $logStr.=sprintf("[%s]:%s".PHP_EOL,$key,$logDatum);
        }
        $logStr.= "============================ Log End ============================".PHP_EOL.PHP_EOL;
        $this->writeFile($logStr);
    }
    
    private function writeFile(string $logStr){
	    $resource = "";
	    try {
		    $resource = fopen($this->fullLogFileRealPath,"a+");
		    fwrite($resource,$logStr);
	    }catch (\Exception $exception){
		
	    } finally {
		    fclose($resource);
	    }
    }
	
	/**
	 * 记录 trace 等级日志
	 * @param $data
	 */
    public function trace($data){
    	if(is_array($data)){
		    $this->writeFile($this->getLogFormatStr($data,LogType::TRACE));
	    }else{
		    $this->writeFile($this->getLogFormatStrLine(settype($data,"string"),LogType::TRACE));
	    }
    }
    
    /**
	 * 记录 debug 等级日志
	 * @param $data
	 */
	public function debug($data){
		if(is_array($data)){
			$this->writeFile($this->getLogFormatStr($data,LogType::DEBUG));
		}else{
			$this->writeFile($this->getLogFormatStrLine(settype($data,"string"),LogType::DEBUG));
		}
	}
	
	/**
	 * 记录 info 等级日志
	 * @param $data
	 */
	public function info($data){
		if(is_array($data)){
			$this->writeFile($this->getLogFormatStr($data,LogType::INFO));
		}else{
			$this->writeFile($this->getLogFormatStrLine(settype($data,"string"),LogType::INFO));
		}
	}
	
	/**
	 * 记录 warn 等级日志
	 * @param $data
	 */
	public function warn($data){
		if(is_array($data)){
			$this->writeFile($this->getLogFormatStr($data,LogType::WARN));
		}else{
			$this->writeFile($this->getLogFormatStrLine(settype($data,"string"),LogType::WARN));
		}
	}
	
	/**
	 * 记录 error 等级日志
	 * @param $data
	 */
	public function error($data){
		if(is_array($data)){
			$this->writeFile($this->getLogFormatStr($data,LogType::TRACE));
		}else{
			$this->writeFile($this->getLogFormatStrLine(settype($data,"string"),LogType::ERROR));
		}
	}
	
	/**
	 * 记录 fatal 等级日志
	 * @param $data
	 */
	public function fatal($data){
		if(is_array($data)){
			$this->writeFile($this->getLogFormatStr($data,LogType::FATAL));
		}else{
			$this->writeFile($this->getLogFormatStrLine(settype($data,"string"),LogType::FATAL));
		}
	}
	
	/**
	 * 返回日志格式字符串
	 *
	 * @param array  $data      记录的日志数据
	 * @param string $logLev    日志等级
	 *
	 * @return string
	 */
    private function getLogFormatStr(array $data, $logLev){
    	$logStr = "";
	    foreach ($data as $key=>$datum) {
	    	if(is_array($datum)){
			    $logStr .= $this->getLogFormatStrLine(json_encode($datum,JSON_UNESCAPED_UNICODE),$logLev);
		    }else if (is_bool($datum)){
			    $logStr .= $this->getLogFormatStrLine((bool)$datum?"true":"false",$logLev);
		    }else{
			    $logStr .= $this->getLogFormatStrLine(settype($datum,"string"),$logLev);
		    }
    	}
        return $logStr;
    }
	
	/**
	 * 获取单行数据
	 * @param string $str
	 * @param        $logLev
	 *
	 * @return string
	 */
    private function getLogFormatStrLine(string $str,$logLev):string {
        return sprintf(date("Y-m-d H:i:s",time())."【%s】 %s".PHP_EOL,$logLev,$str);
    }


    // ************************************************************************ //
    // ******************************** Getter ******************************** //
    // ************************************************************************ //
    /**
     * @return string
     */
    public function getLogRootPath(): string
    {
        return $this->logRootPath;
    }
}