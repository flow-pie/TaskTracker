<?php
// Include Composer's autoloader
require_once __DIR__ . '/../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Processor\WebProcessor;

/**
 * Creates and returns a configured Monolog logger instance.
 *
 * @return Logger
 */
function get_logger(): Logger {
    // Create a new Logger channel (e.g., 'task_tracker')
    $log = new Logger('task_tracker');

    // Create a handler to log records to a file named 'app.log'
    $log->pushHandler(new StreamHandler(__DIR__ . '/../logs/app.log', Logger::DEBUG));
    
    // (Optional but recommended) Add extra data to logs, like IP address and request URI
    $log->pushProcessor(new WebProcessor());

    return $log;
}
