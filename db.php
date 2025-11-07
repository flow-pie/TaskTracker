<?php
ini_set("session.use_only_cookies", 1);
ini_set("session.use_trans_sid", 0);
session_set_cookie_params([
    "lifetime" => 0,
    "path" => "/",
    "domain" => "",
    "secure" => true,
    "httponly" => true,
    "samesite" => "Lax",
]);

session_start();

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

try {
    $db = new PDO("sqlite:task_tracker.db");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        failed_login_attempts INTEGER DEFAULT 0,
        last_login_attempt DATETIME
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        task TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS audit_log (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
           user_id INTEGER,
           user_email TEXT,
           event_type TEXT NOT NULL,
           ip_address TEXT,
           details TEXT
       )");
} catch (PDOException $e) {
    log_event("Database Connection Error: " . $e->getMessage(), "error");
    die("Database connection failed. Please try again later.");
}
