<?php
/**
 * The purpose of this script is to initialise environment for testing GoogleAuthenticatorClient functionality
 *
 * @author  Yuriy Akopov
 * @date    2013-03-10
 */

// scrutiny level for testing purposes is supposed to be high
error_reporting(E_ALL|E_STRICT);
ini_set('display_errors', 1);

// loading PHPUnit's own autoloader for it to be able to load itself
require_once 'PHPUnit/Autoload.php';

// loading classes to be tested
require_once('../classes/GoogleAuthenticatorClient.php');

// loading test parent class
require_once('GoogleAuthenticatorClientTest.php');

