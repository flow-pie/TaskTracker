## Overview

This document outlines all security features implemented in the project, with **exact file locations**, **line references (approx.)**, and **short explanations** of their purpose and protection level.

### 1. Enforce Authorization Checks on Every Request

**File:** `index.php`

**Implementation:***

Every page (e.g., `index.php`) begins with:
```php
    if (!isset($_SESSION["user_id"])) {
        header("Location: login.php");
        exit();
    }
```

### 2. Store Passwords Using Strong Hashing (Argon2)

**File:** `func/passwd.php`
**Implementation:**

* `hash_pass($password)` — uses **Argon2id** for strong password hashing.
* Adds a **pepper** via `hash_hmac('sha256', $password, $pepper)` before hashing.
* `verify_pass($input_pass, $hashed_pass)` rehashes input with pepper and verifies using `password_verify`.

**Purpose:** Prevent rainbow table and brute-force attacks.
**OWASP Ref:** [A07: Identification and Authentication Failures](https://owasp.org/Top10/A07_Identification_and_Authentication_Failures/)


### 3. Define What Data Is Private and Public

**Implementation:**

Only logged-in users can view their own tasks (tasks table filtered by user_id).
```php
    // Fetch tasks for the current user
    $stmt = $db->prepare(
        "SELECT id, task, status FROM tasks WHERE user_id = :user_id ORDER BY created_at DESC",
    );
    $stmt->bindParam(":user_id", $userId);
    $stmt->execute();
    $tasks = $stmt->fetchAll(PDO::FETCH_ASSOC)

```

Public access is limited to login.php and register.php.

No sensitive information (like password hashes) is ever exposed to the client.


### 4. Use Secure HTTP Headers

**Implementation:**

Found at the top of `index.php:`

```php
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self';");
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");

```

Protects against clickjacking, XSS, MIME-sniffing, and unauthorized script loading.


### 5. Dependency Scanning for Vulnerable Packages

**Implementation:**

The project uses minimal dependencies (pure PHP + PDO).

Future updates include using `composer audit` or Dependabot for dependency scanning.

> Status: ⚠️ Partially implemented (manual dependency control).

### 6. Strong Session Management (Secure Cookies)

**File:** `db.php`, 
**Lines:** Session is configured securily in db.php file using `ini_set()` func.
**Implementation:**

* Secure session configuration `db.php`:

  ```php
  ini_set('session.cookie_httponly', 1);
  ini_set('session.cookie_secure', 1);
  ini_set('session.use_strict_mode', 1);
  session_start();
  ```
* Session regenerated on login `login.php`:

  ```php
  session_regenerate_id(true);
  ```
* Session destroyed on logout `logout.php`:

  ```php
    session_unset();
    session_destroy();
  ```

**Purpose:** Prevent session hijacking and fixation.
**OWASP Ref:** [A07: Identification and Authentication Failures](https://owasp.org/Top10/A07_Identification_and_Authentication_Failures/)

### 7. Verify Updates Before Deploying to Production

**Implementation:**

Manual review before deployment (since this is a coursework project).

> Status: ⚠️ Partially implemented.

### 8. Log All Login Attempts, Task Modifications, and Errors
**File:** `logger.php`

**Implementation:**

Error handling and user feedback ($error variable) in index.php and login.php and logs stored in `app.log` file.

```php
    <?php
    function log_event($msg, $level = "info")
    {
        $line = date("c") . " [$level] " . $msg . PHP_EOL;
        file_put_contents(__DIR__ . "/logs/app.log", $line, FILE_APPEND | LOCK_EX);
    }

```

### 9.Validate and Sanitize External URLs

**File:** `index.php`

**Lines:** ~100-105

**Implementation:**

``` php
    $userEmail = $user ? htmlspecialchars($user["email"]) 

```

* Centralized `htmlspecialchars()` function used across forms.
* Validates email, usernames, numeric IDs, etc.

**Purpose:** Ensure only safe data is processed or stored.
**OWASP Ref:** [A01: Broken Access Control](https://owasp.org/Top10/A01_Broken_Access_Control/)

### 10. SQL Injection Prevention

**File:** `index.php`, `login.php`, `register.php` etc.,
**Implementation:**

* All database queries in above mentioned files uses **prepared statements** via PDO:

  ```php
  $stmt = $db->prepare(
                    "INSERT INTO tasks (user_id, task) VALUES (:user_id, :task)",
                );
                $stmt->bindParam(":user_id", $userId);
                $stmt->bindParam(":task", $task);
                $stmt->execute();
  ```
* No user input directly concatenated into SQL queries.

**Purpose:** Prevent SQL injection attacks.
**OWASP Ref:** [A03: Injection](https://owasp.org/Top10/A03_Injection/)


### 11. Cross-Site Scripting (XSS) Protection

**File:** All the files where user data need to be echoed eg `index.php`, `login.php`, `register.php` 

**Lines:** Wherever user data is output. In short anywhere `htmlspecialchars() ` method is used.

**Implementation:**

* All echoed user data sanitized with `htmlspecialchars($var, ENT_QUOTES, 'UTF-8')`.
* No unescaped HTML output from user input.

**Purpose:** Prevent malicious scripts from executing on the client browser.
**OWASP Ref:** [A03: Injection (XSS Subtype)](https://owasp.org/Top10/A03_Injection/)


### 12. Content Security Policy (CSP)

**File:** `index.php`

**Lines:** In the headers

**Implementation:**

```php
header(
    "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self';",
);
```

**Purpose:** Restrict what sources the browser can load (prevents inline script execution).
**OWASP Ref:** [A05: Security Misconfiguration](https://owasp.org/Top10/A05_Security_Misconfiguration/)




### 13. Token-Based CSRF Protection

**File:** `index.php`
**Lines:** ~35 - 49

**Implementation:**

* Tokens stored in session, added to forms, and verified on submission.

```php
 if (
        !isset($_POST["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])
    ) {
        $error = "Invalid CSRF token. Action blocked.";
    } else {
        if (isset($_POST["add_task"])) {
            if (empty($_POST["task"])) {
                $error = "Task description cannot be empty.";
            }
            .....
```

**Purpose:** Prevent cross-site request forgery attacks.
**OWASP Ref:** [A05: Security Misconfiguration](https://owasp.org/Top10/A05_Security_Misconfiguration/)



### 14. Role-Based Access Control (RBAC)

**File:** `middleware/auth_guard.php`
**Lines:** ~10–30
**Implementation:**

```php
if ($_SESSION['role'] !== 'admin') {
    header('Location: /403.php');
    exit;
}
```

**Purpose:** Restrict access to sensitive routes based on roles.
