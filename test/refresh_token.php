<?php

use OAuth2\YiCKJOAuth2Client;

include_once("./index.php");

$oauthClient = YiCKJOAuth2Client::getInstance($oauthConfig);

$oauthClient->refreshAccessToken($_GET["access_token"]);