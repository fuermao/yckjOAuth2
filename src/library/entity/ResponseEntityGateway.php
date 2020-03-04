<?php


namespace OAuth2\library\entity;


class ResponseEntityGateway implements ResponseEntityInterface
{
	private $s_code;
	
	private $s_msg;
	
	private $s_ts;
	
	private $s_data;
	
	/**
	 * @return mixed
	 */
	public function getCode():int
	{
		return (int)$this->s_code;
	}
	
	/**
	 * @param mixed $s_code
	 */
	public function setCode(int $s_code): void
	{
		$this->s_code = $s_code;
	}
	
	/**
	 * @return mixed
	 */
	public function getMsg():string
	{
		return $this->s_msg;
	}
	
	/**
	 * @param mixed $s_msg
	 */
	public function setMsg(string $s_msg): void
	{
		$this->s_msg = $s_msg;
	}
	
	/**
	 * @return mixed
	 */
	public function getSTs()
	{
		return $this->s_ts;
	}
	
	/**
	 * @param mixed $s_ts
	 */
	public function setSTs($s_ts): void
	{
		$this->s_ts = $s_ts;
	}
	
	/**
	 * @return mixed
	 */
	public function getData():array
	{
		return $this->s_data;
	}
	
	/**
	 * @param mixed $s_data
	 */
	public function setData(array $s_data): void
	{
		$this->s_data = $s_data;
	}
}