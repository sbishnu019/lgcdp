<?php

use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;

//setup autoloader
require '../vendor/autoload.php';


//prepare app
$settings = require '../api/src/settings.php';
$app = new \Slim\App($settings);

//register routes
require '../api/src/routes.php';

//register dependencies
require '../api/src/dependencies.php';


//run app
$app->run();