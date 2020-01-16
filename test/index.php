<?php

use function Composer\Autoload\includeFile;

if(!defined("OAUTH_DS")){
    define("OAUTH_DS",DIRECTORY_SEPARATOR);
}
$vendorPath = realpath(dirname(__DIR__)).OAUTH_DS."vendor".OAUTH_DS."autoload.php";
include_once($vendorPath);