<?php


namespace OAuth2\library\logger;


final class Logger
{
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
        $this->logRootPath = dirname(dirname(dirname(__DIR__))).DIRECTORY_SEPARATOR."runtime".DIRECTORY_SEPARATOR."logs".DIRECTORY_SEPARATOR;
        // 按照年月日划分日志目录
        $this->logRootPath.= date("Y",time()).DIRECTORY_SEPARATOR.date("m",time()).DIRECTORY_SEPARATOR;
    }

    /**
     * 初始化操作
     */
    private function init():void {
        // 创建日志目录
        if(!is_dir(self::$instance->logRootPath)){
            mkdir(self::$instance->logRootPath,0766,true);
        }
        // 创建日志文件
        $this->fullLogFileRealPath = $this->logRootPath.$this->logFileName."-".date("d",time()).".log";
        if(!file_exists($this->fullLogFileRealPath)){
            file_put_contents($this->fullLogFileRealPath,"");
        }
    }

    /**
     * 获取实例化
     * @param string $logFileName 不包含后缀
     * @return Logger
     */
    public static function getInstance(string $logFileName): Logger{
        if(self::$instance == null){
            self::$instance = new self();
        }
        self::$instance->logFileName = $logFileName;
        self::$instance->init();
        return self::$instance;
    }

    /**
     * 将日志数据写入日志中
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




        $logData = array_merge($logData,$data);

        $logStr = "";
        $logStr.= "=========================== Log Start ===========================".PHP_EOL;
        foreach ($logData as $key=>$logDatum) {
            if(is_array($logDatum)){
                $logDatum = json_encode($logDatum);
            }
            $logStr.=sprintf("[%s]:%s".PHP_EOL,$key,$logDatum);
        }
        $logStr.= "============================ Log End ============================".PHP_EOL.PHP_EOL;

        $resource = "";
        try {
            $resource = fopen($this->fullLogFileRealPath,"a+");
            fwrite($resource,$logStr);
        }catch (\Exception $exception){

        } finally {
            fclose($resource);
        }
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