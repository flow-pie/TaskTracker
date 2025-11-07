<?php
require_once "db.php";
require_once "func/passwd.php";
require_once "func/logger.php";

global $db;

/*
 * This script handles the user login process for the Task Tracker application.
 *
 * It performs the following actions:
 * 1.  Includes the database connection and initializes the global $db variable.
 * 2.  Defines constants for login security, specifically for account lockout
 *     (MAX_LOGIN_ATTEMPTS and LOCKOUT_TIME).
 * 3.  Checks if a user is already logged in via their session; if so, it redirects
 *     them to the main index page.
 * 4.  Handles the form submission (POST request) for login.
 * 5.  Validates the CSRF token to prevent cross-site request forgery attacks.
 * 6.  Validates that the email and password fields are not empty.
 * 7.  Fetches the user from the database based on the provided email.
 * 8.  Implements a brute-force protection mechanism:
 *     - It checks if the account is locked due to too many failed login attempts.
 *     - If an account is locked, it displays an error and prevents login for a
 *       set duration.
 * 9.  If the account is not locked, it verifies the provided password against the
 *     hashed password stored in the database.
 * 10. On successful login:
 *     - Resets the failed login attempt counter in the database.
 *     - Regenerates the session ID to prevent session fixation.
 *     - Stores the user's ID in the session.
 *     - Redirects the user to the main application page (index.php).
 * 11. On failed login:
 *     - Increments the failed login attempt counter in the database.
 *     - Introduces a short delay (sleep) to slow down brute-force attacks.
 *     - Displays a generic "Invalid email or password" error to avoid
 *       user enumeration.
 * 12. Renders the HTML for the login page, including the form, error messages,
 *     and a link to the registration page.
 */

 $log = get_logger();

$error = "";

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 900;

if (isset($_SESSION["user_id"])) {
    header("Location: index.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["login"])) {
    if (
        !isset($_POST["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])
    ) {
        $error = "Invalid CSRF token. Please try again.";
        $log->warning('CSRF_VALIDATION_FAIL', ['email' => $_POST["email"]]);
    } elseif (empty($_POST["email"]) || empty($_POST["password"])) {
        $error = "Email and password are required.";
    } else {
        $email = $_POST["email"];
        $input_pass = $_POST["password"];

        $stmt = $db->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->bindParam(":email", $email);
        $stmt->execute();

        session_regenerate_id(true);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $is_locked = false;
            if ($user["last_login_attempt"] !== null) {
                $attempts = $user["failed_login_attempts"];
                $last_attempt_time = strtotime($user["last_login_attempt"]);
                if (
                    $attempts >= MAX_LOGIN_ATTEMPTS &&
                    time() - $last_attempt_time < LOCKOUT_TIME
                ) {
                    $is_locked = true;
                }
            }

            if ($is_locked) {
                $error =
                    "Too many failed login attempts. Please wait 15 minutes and try again.";
                http_response_code(429);
                $msg =
                    "User ID " .
                    $user["id"] .
                    " is locked out due to too many failed login attempts.";
                log_event($msg, "info");
            } else {
                if (verify_pass($input_pass, $user["password"])) {
                    // Reset failed login attempts in DB
                    $stmt = $db->prepare(
                        "UPDATE users SET failed_login_attempts = 0, last_login_attempt = NULL WHERE id = :id",
                    );
                    $stmt->bindParam(":id", $user["id"]);
                    $stmt->execute();

                    // Regenerate session ID to prevent fixation. This must be done before any other output.
                    session_regenerate_id(true);
                    $_SESSION["user_id"] = $user["id"];

                    $log->info('LOGIN_SUCCESS', ['user_id' => $user['id'], 'email' => $email]);

                    // Redirect to the main page.
                    header("Location: index.php");
                    exit();
                } else {
                    // Logic for failed attempt
                    $stmt = $db->prepare(
                        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_login_attempt = datetime('now') WHERE id = :id",
                    );
                    $stmt->bindParam(":id", $user["id"]);
                    $stmt->execute();
                    sleep(2);
                    $log->notice('LOGIN_FAIL_PASSWORD', ['user_id' => $user['id'], 'email' => $email]);

                    $error = "Invalid email or password.";
                }
            }
        } else {
            sleep(2);
            $log->notice('LOGIN_FAIL_NO_USER', ['email' => $email]);
            $error = "Invalid email or password.";
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login - Task Tracker</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="container">
        <h2>Login to Task Tracker</h2>
        <?php if ($error): ?>
            <p class="error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <?php if (isset($_GET["registered"])): ?>
            <p class="success">Registration successful! You can now log in.</p>
        <?php endif; ?>
        <form action="login.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(
                $_SESSION["csrf_token"],
            ); ?>">
            <label for="email">Email</label>
            <input type="email" name="email" required placeholder="Enter Email">
            <label for="password">Password</label>
            <input type="password" name="password" required placeholder="Enter Password">
            <button type="submit" name="login">Login</button>
        </form>
        <p>Don't have an account? <a href="register.php">Register here</a>.</p>
    </div>
</body>
</html>
