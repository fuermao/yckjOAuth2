<?php
declare(strict_types = 1);

namespace OAuth2\library\tools;


/**
 * Class ArraysToObject
 * 通过PHP反射机制获取实例类及其属性以及方法
 * 思路：
 * 1. 通过字符串或者命名空间或 ResponseEntity::class 获取反射信息
 * 2. 判断是否存在构造器
 *      2.1 构造函数为空则考虑通过setter方法对类中的实例进行赋值
 *      2.2 如果存在构造函数，则获取构造函数的参数列表
 *          2.2.1 如果参数列表为空，则直接通过newInstance()方法创建实例
 *          2.2.2 如果参数列表不为空，则从原数组中获取响应键所对应的值（且键必须与构造器中
 *                的参数名称对应）。如果不对应则无法创建实例抛出异常
 * 3. 最后，获取从反射类中获取公有属性以及私有属性，通过原数组中的键所对应值对类中的属性就行赋值。
 * 4. 返回实例
 *
 * @package OAuth2\library\tools
 */
class ArraysToObject
{
	/**
	 * @var \ReflectionClass 获取反射类信息
	 */
	private $reflectionClass;
	
	/**
	 * @var array 转为为对象的目标数组
	 */
	private $targetArray;
	
	/**
	 * @var Object 实例对象
	 */
	private $clazz;
	
	/**
	 * @var \OAuth2\library\tools\ArraysToObject ArraysToObject的实例信息
	 */
	private static $instance;
	
	/**
	 * ArraysToObject constructor.
	 *
	 * @param string $nameSpace 命名空间字符串
	 *
	 * @throws \ReflectionException 反射异常
	 */
	private function __construct(string $nameSpace){
		$this->reflectionClass = new \ReflectionClass($nameSpace);
		// printf($this->reflectionClass->getFileName());
		// if(!file_exists($this->reflectionClass->getFileName())){
		// 	throw new \ReflectionException("Not Found ".$nameSpace." Class File!");
		// }else{
		// 	// 加载文件
		// 	require_once($this->reflectionClass->getFileName());
		// }
	}
	
	/**
	 * 根据命名空间获取实例信息
	 *
	 * @param string $nameSpace     class的命名空间
	 * @param array  $src           转为为对象的目标数组
	 *
	 * @throws \ReflectionException
	 * @return \OAuth2\library\tools\ArraysToObject
	 */
	public static function getInstance(string $nameSpace,array $src): \OAuth2\library\tools\ArraysToObject
	{
		self::$instance = new self($nameSpace);
		self::$instance->targetArray = $src;
		// 返回实例信息
		return self::$instance;
	}
	
	/**
	 * 转换对象
	 *
	 * @throws \ReflectionException
	 */
	public function exchangeToObject(){
		// 获取实例信息
		$this->clazz = $this->getClazzInstance();
		// 属性赋值
		$filedList = $this->reflectionClass->getProperties();
		// 属性赋值
		$this->filedAssignment($this->targetArray,$this->clazz);
		return $this;
	}
	
	/**
	 * 获取实例
	 * @throws \ReflectionException 反射异常
	 * @return object
	 */
	private function getClazzInstance(){
		// 获取构造器
		$constructor = $this->reflectionClass->getConstructor();
		// 如果构造器为空
		if($constructor == null){
			return $this->reflectionClass->newInstance();
		}
		// 判断构造函数是否可被访问
		// TODO:后面考虑是否支持到非公共构造的支持；
		if(!$constructor->isPublic()){
			throw new \ReflectionException("The Constructor Isn't Public!");
		}
		// 如果构造器不为空，且无构造参数
		$constructorParamList = $constructor->getParameters();
		if(sizeof($constructorParamList) == 0){
			return $this->reflectionClass->newInstance();
		}
		// 定义参数列表值数组
		$args = $this->castMethodParamType($this->targetArray,$constructor);
		return $this->reflectionClass->newInstanceArgs($args);
	}
	
	/**
	 * 强制转换参数列表
	 *
	 * @param array             $param
	 * @param \ReflectionMethod $methodRef 需要获取参数列表类型的反射关系
	 *
	 * @throws \ReflectionException
	 * @return array
	 */
	private function castMethodParamType(array $param,\ReflectionMethod $methodRef){
		$castParam = [];
		// 返回参数值
		$methodParamList = $methodRef->getParameters();
		// 如果为空，则返回空数组
		if(sizeof($methodParamList) == 0){
			return $castParam;
		}
		// 如果不为空则遍历
		// 如果构造参数列表
		if(!is_array($methodParamList)){
			throw new \ReflectionException("Constructor Params Get Failed!");
		}
		foreach ($methodParamList as $parameter){
			// debug信息参数信息
			// $this->debugParameter($parameter);
			// 判断原数组中是否包含该参数
			// debug
			// print_r(sprintf("参数[%s]是否在%s中：%s",
			// 	$parameter->getName(),
			// 	json_encode($param,JSON_UNESCAPED_UNICODE),
			// 	var_export(array_key_exists($parameter->getName(),$param),true)
			// ));
			if(array_key_exists($parameter->getName(),$param)){
				switch (true){
					case is_array($this->targetArray[$parameter->getName()]):
						$castParam[$parameter->getPosition()] = (array)$param[$parameter->getName()];
						break;
					case is_bool($this->targetArray[$parameter->getName()]):
						$castParam[$parameter->getPosition()] = (boolean)$param[$parameter->getName()];
						break;
					case is_numeric($this->targetArray[$parameter->getName()]):
						if (is_int($this->targetArray[$parameter->getName()])){
							$castParam[$parameter->getPosition()] = (int)$param[$parameter->getName()];
						}elseif (is_float($this->targetArray[$parameter->getName()])){
							$castParam[$parameter->getPosition()] = (float)$param[$parameter->getName()];
						}elseif (is_double($this->targetArray[$parameter->getName()])){
							$castParam[$parameter->getPosition()] = (double)$param[$parameter->getName()];
						}else{
							throw new \ReflectionException("Array's Key[".$parameter->getName()."] Cast Number Failed!");
						}
						break;
					case is_string($this->targetArray[$parameter->getName()]):
						$castParam[$parameter->getPosition()] = strval($param[$parameter->getName()]);
						break;
					case is_null($this->targetArray[$parameter->getName()]):
						$castParam[$parameter->getPosition()] = null;
						break;
					default:
						throw new \ReflectionException("Can't Identify Param Type!");
						break;
				}
				$castParam[$parameter->getPosition()] = $param[$parameter->getName()];
			}
			// 如果不包含，在判断该值是否为必传构造参数
			// 非必传且是该构造参数是数组且默认值可用
			else if($parameter->isOptional() && $parameter->isDefaultValueAvailable()){
				$castParam[$parameter->getPosition()] = $parameter->getDefaultValue();
			}
			// 既不存在与源数组中，又是必传参数，那么只能人工赋值
			else{
				// 如果参数是数组，那么给空数组
				if($parameter->isArray()){
					$castParam[$parameter->getPosition()] = [];
				}
				// TODO：可尝试支持其他的类
				// 其他的只能抛出异常
				else {
					throw new \ReflectionException("Method Parameter[".$parameter->getName()."] Cant't Get Param Type!");
				}
			}
		}
		return $castParam;
	}
	
	/**
	 * 给实例属性赋值
	 * 1. 获取所有的动态属性
	 *      1.1 判断源数组中是否有键
	 *      1.2 暴力赋值(TODO:暴力赋值不可取！)
	 * 2. 静态属性赋值
	 * @param array $param 需要赋值的属性
	 * @param mixed $clazz 操作的实例
	 *
	 * @return mixed 返回已实例的对象
	 */
	private function filedAssignment(array $param,$clazz) {
		// 获取目标类的所有动态属性
		$filedList = $this->reflectionClass->getProperties();
		$staticFieldList = $this->reflectionClass->getStaticProperties();
		// 两种属性都为空则直接退出执行本函数
		if(sizeof($filedList) == 0 && sizeof($staticFieldList) == 0){
			return $clazz;
		}
		// 遍历动态属性
		foreach ($filedList as $field){
			// 暴力赋值
			// 设置属性可被访问
			$field->setAccessible(true);
			// 在目标数组中存在就赋值
			if(array_key_exists($field->getName(),$param)){
				$field->setValue($clazz,$param[$field->getName()]);
			}
		}
		// 遍历所有静态属性（不一定有用）
		foreach ($staticFieldList as $staticFiledName){
			if(array_key_exists($staticFiledName,$param)){
				$this->reflectionClass->setStaticPropertyValue($staticFiledName,$param[$staticFiledName]);
			}
		}
		return $clazz;
	}
	
	/**
	 * 通过反射调用方法
	 * @param string $methodName    调用方法名称
	 * @param mixed  ...$arg        参数列表
	 *
	 * @throws \ReflectionException
	 * @return mixed
	 */
	public function invokeMethod(string $methodName,...$arg){
		if($this->clazz == null){
			throw new \ReflectionException("The Reflect Object is null,Please call exchangeToObject method first!");
		}
		// 根据方法名称获取方法的反射
		$method = $this->reflectionClass->getMethod($methodName);
		// 判断方法是否为抽象方法
		if($method->isAbstract()){
			throw new \ReflectionException("The Method[".$methodName."()] Is Abstract Method");
		}
		// 判断方法是否受保护或者私有
		if($method->isPrivate() || $method->isProtected()){
			throw new \ReflectionException("The Method[".$methodName."()] Is Private Or Protect");
		}
		// 判断参数是否正确
		if($method->getNumberOfParameters() != sizeof($arg)){
			throw new \ReflectionException("The Method[".$methodName."()] Parameter Isn't Match!");
		}
		
		return $method->invokeArgs($this->clazz,$arg);
	}
	
	/**
	 * debug 方法的参数信息
	 *
	 * @param \ReflectionParameter $parameter
	 *
	 * @throws \ReflectionException
	 */
	private function debugParameter(\ReflectionParameter $parameter):void {
		echo PHP_EOL;
		printf("参数名称：%s",$parameter->getName());
		echo PHP_EOL;
		// Todo:如果参数列表中又是一个类，则需要重新递归获取其对象
		if($parameter->getClass()){
			printf("在参数列表中的位置：%s",$parameter->getClass()->getName());
		}
		echo PHP_EOL;
		printf("在参数列表中的位置：%s",$parameter->getPosition());
		echo PHP_EOL;
		printf("是否为必传参数：%s",var_export($parameter->isOptional(),true));
		echo PHP_EOL;
		printf("是否为数组：%s",var_export($parameter->isArray(),true));
		echo PHP_EOL;
		printf("是否有参数类型设置：%s",var_export($parameter->hasType(),true));
		echo PHP_EOL;
		printf("参数默认值是否可用：%s",var_export($parameter->isDefaultValueAvailable(),true));
		echo PHP_EOL;
		if($parameter->isDefaultValueAvailable()){
			printf("参数默认值：%s",var_export($parameter->getDefaultValue(),true));
		}
		echo PHP_EOL;
	}
	
	/**
	 * debug 属性信息
	 * @param \ReflectionProperty $field
	 */
	private function debugFiled(\ReflectionProperty $field,$clazz):void {
		// 设置其可被访问
		$field->setAccessible(true);
		printf("属性名称：%s",$field->getName());
		echo PHP_EOL;
		if($field->getDeclaringClass()){
			printf("属性类型：%s",$field->getDeclaringClass()->getName());
			echo PHP_EOL;
		}
		// 属性权限
		if($field->isPublic()){
			$accessStr = 'public access';
		}elseif ($field->isProtected()){
			$accessStr = 'protected access';
		}else if ($field->isPrivate()){
			$accessStr = 'private access';
		}else{
			$accessStr = 'default access';
		}
		printf("属性权限：%s",$accessStr);
		echo PHP_EOL;
		// 是否被初始化
		printf("是否初始化：%s",var_export($field->isInitialized($clazz),true));
		echo PHP_EOL;
		printf("是否默认属性：%s",var_export($field->isDefault(),true));
		echo PHP_EOL;
		// 属性值
		printf("属性值：%s",json_encode($field->getValue($clazz),JSON_UNESCAPED_UNICODE));
		echo PHP_EOL;
		echo PHP_EOL;
	}
	
	/**
	 * 获取实例
	 * @return Object
	 */
	public function getClazz(): Object
	{
		return $this->clazz;
	}
}