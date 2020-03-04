<?php


namespace OAuth2\library\entity;


interface ResponseEntityInterface
{
	/**
	 * 设置状态码
	 * @param int $code
	 */
	public function setCode(int $code):void;
	
	/**
	 * 设置内容数据
	 * @param $data
	 */
	public function setData(array $data):void ;
	
	/**
	 * 设置消息内容
	 * @param string $msg
	 */
	public function setMsg(string $msg):void ;
	
	/**
	 * 获取消息实体状态码
	 * @return int
	 */
	public function getCode():int ;
	
	/**
	 * 获取消息实体内容
	 * @return mixed
	 */
	public function getData():array ;
	
	/**
	 * 获取消息内容
	 * @return string
	 */
	public function getMsg():string ;
}