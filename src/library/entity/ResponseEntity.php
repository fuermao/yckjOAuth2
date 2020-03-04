<?php

namespace OAuth2\library\entity;


class ResponseEntity implements ResponseEntityInterface
{
	private $code;
	
	private $msg;
	
	private $data;
	
	/**
	 * ResponseEntity constructor.
	 *
	 * @param int                                     $code
	 * @param string                                  $msg
	 * @param array                                   $data
	 */
	public function __construct(
		int $code,
		string $msg,
		array $data
	){
		$this->code = $code;
		$this->msg = $msg;
		$this->data = $data;
	}
	
	/**
	 * @return int
	 */
	public function getCode():int
	{
		return $this->code;
	}
	
	/**
	 * @param int $code
	 */
	public function setCode(int $code): void
	{
		$this->code = $code;
	}
	
	/**
	 * @return string
	 */
	public function getMsg():string
	{
		return $this->msg;
	}
	
	/**
	 * @param string $msg
	 */
	public function setMsg(string $msg): void
	{
		$this->msg = $msg;
	}
	
	/**
	 * @return array
	 */
	public function getData():array
	{
		return $this->data;
	}
	
	/**
	 * @param array $data
	 */
	public function setData(array $data): void
	{
		$this->data = $data;
	}
}