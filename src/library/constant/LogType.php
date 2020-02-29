<?php


namespace OAuth2\library\constant;


class LogType
{
	/**
	 * 很低的日志级别
	 */
	const TRACE = "TRACE";
	
	/**
	 * 指出细粒度信息事件对调试应用程序是非常有帮助的
	 */
	const DEBUG = "DEBUG";
	
	/**
	 * 消息在粗粒度级别上突出强调应用程序的运行过程
	 */
	const INFO = "INFO";
	
	/**
	 * 表明会出现潜在错误的情形，有些信息不是错误信息
	 */
	const WARN = "WARN";
	
	/**
	 * 指出虽然发生错误事件，但仍然不影响系统的继续运行
	 */
	const ERROR = "ERROR";
	
	/**
	 * 指出每个严重的错误事件将会导致应用程序的退出。这个级别比较高了。
	 */
	const FATAL = "FATAL";
	
}