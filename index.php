<?php
/*
 * Main dashboard page for the Task Tracker application.
 *
 * This script handles the core functionality for a logged-in user. It allows users to
 * view, add, update, and delete their tasks.
 *
 * Key functionalities include:
 * - Session management to ensure only authenticated users can access the page.
 * - CSRF token validation for all form submissions to prevent cross-site request forgery.
 * - Database operations (INSERT, UPDATE, DELETE, SELECT) for managing tasks,
 *   all performed using prepared statements to prevent SQL injection.
 * - Fetching user-specific data to personalize the dashboard.
 * - Rendering the HTML structure for the task list and management forms.
 */
require_once "db.php";
require_once "func/logger.php";
global $db;

// Security Headers
header(
    "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self';",
);
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit();
}

$userId = $_SESSION["user_id"];
$error = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (
        !isset($_POST["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])
    ) {
        $error = "Invalid CSRF token. Action blocked.";
        $log = get_logger(true);
        $log->warning('CSRF_VALIDATION_FAIL', ['user_id' => $userId]);
    } else {
        if (isset($_POST["add_task"])) {
            if (empty($_POST["task"])) {
                $error = "Task description cannot be empty.";
            } else {
                $task = $_POST["task"];
                $stmt = $db->prepare(
                    "INSERT INTO tasks (user_id, task) VALUES (:user_id, :task)",
                );
                $stmt->bindParam(":user_id", $userId);
                $stmt->bindParam(":task", $task);
                $stmt->execute();

                $newTaskId = $db->lastInsertId(); 
                $log = get_logger(false);
                $log->info('CREATE_TASK', [
                    'user_id' => $userId,
                    'task_id' => $newTaskId,
                    'task'    => $task
                ]);
                
                header("Location: index.php");
                exit();
            }
        }

        if (isset($_POST["update_task_status"])) {
            $taskId = $_POST["task_id"];
            $status = $_POST["status"];
            if (in_array($status, ["pending", "in_progress", "completed"])) {
                $stmt = $db->prepare(
                    "UPDATE tasks SET status = :status WHERE id = :id AND user_id = :user_id",
                );
                $stmt->bindParam(":status", $status);
                $stmt->bindParam(":id", $taskId);
                $stmt->bindParam(":user_id", $userId);
                $stmt->execute();
                log_event("Task added for user ID $userId", "info");
                header("Location: index.php");
                exit();
            }
        }

        if (isset($_POST["delete_task"])) {
            $taskId = $_POST["task_id"];
            $stmt = $db->prepare(
                "DELETE FROM tasks WHERE id = :id AND user_id = :user_id",
            );
            $stmt->bindParam(":id", $taskId);
            $stmt->bindParam(":user_id", $userId);
            $stmt->execute();
            log_event("Task added for user ID $userId", "info");
            header("Location: index.php");
            exit();
        }
    }
}

// Fetch tasks for the current user
$stmt = $db->prepare(
    "SELECT id, task, status FROM tasks WHERE user_id = :user_id ORDER BY created_at DESC",
);
$stmt->bindParam(":user_id", $userId);
$stmt->execute();
$tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch user's email for display
$userStmt = $db->prepare("SELECT email FROM users WHERE id = :id");
$userStmt->bindParam(":id", $userId);
$userStmt->execute();
$user = $userStmt->fetch(PDO::FETCH_ASSOC);
$userEmail = $user ? htmlspecialchars($user["email"]) : "User";
?>
<!DOCTYPE html>
<html>
<head>
    <title>Task Tracker</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="dashboard-container">
        <div class="header">
            <h2>Welcome, <?php echo $userEmail; ?>!</h2>
            <form action="logout.php" method="post" style="margin:0;">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(
                    $_SESSION["csrf_token"],
                ); ?>">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        </div>

        <h3>Add a New Task</h3>
        <?php if ($error): ?>
            <p class="error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <form action="index.php" method="post" class="task-form">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(
                $_SESSION["csrf_token"],
            ); ?>">
            <input type="text" name="task" placeholder="Enter new task..." required maxlength="255">
            <button type="submit" name="add_task">Add Task</button>
        </form>

        <h3>Your Tasks</h3>
        <div class="task-list">
            <?php if (empty($tasks)): ?>
                <p>You have no tasks yet. Add one above!</p>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>Task</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($tasks as $task): ?>
                            <tr>
                                <td class="task-description <?php echo htmlspecialchars(
                                    $task["status"],
                                ); ?>">
                                    <?php echo htmlspecialchars(
                                        $task["task"],
                                    ); ?>
                                </td>
                                <td>
                                    <form action="index.php" method="post" class="status-form">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(
                                            $_SESSION["csrf_token"],
                                        ); ?>">
                                        <input type="hidden" name="task_id" value="<?php echo $task[
                                            "id"
                                        ]; ?>">
                                        <select name="status" onchange="this.form.submit()">
                                            <option value="pending" <?php if (
                                                $task["status"] == "pending"
                                            ) {
                                                echo "selected";
                                            } ?>>Pending</option>
                                            <option value="in_progress" <?php if (
                                                $task["status"] == "in_progress"
                                            ) {
                                                echo "selected";
                                            } ?>>In Progress</option>
                                            <option value="completed" <?php if (
                                                $task["status"] == "completed"
                                            ) {
                                                echo "selected";
                                            } ?>>Completed</option>
                                        </select>
                                        <input type="hidden" name="update_task_status" value="1">
                                    </form>
                                </td>
                                <td>
                                    <form action="index.php" method="post">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(
                                            $_SESSION["csrf_token"],
                                        ); ?>">
                                        <input type="hidden" name="task_id" value="<?php echo $task[
                                            "id"
                                        ]; ?>">
                                        <button type="submit" name="delete_task" class="delete-btn">Delete</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
