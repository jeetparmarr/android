<?php
// Initialize session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

header('Content-Type: application/json');
require_once 'config.php';

// ================== PERSISTENT DEVICE ID SOLUTION ==================
function getPersistentDeviceId() {
    // Return existing ID if already generated
    if (!empty($_SESSION['device_id'])) {
        return $_SESSION['device_id'];
    }

    // Generate from stable components
    $fingerprint = implode('|', [
        $_SERVER['HTTP_USER_AGENT'] ?? '',
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
        gethostname() // Server-side component for additional uniqueness
    ]);
    
    $deviceId = hash('sha256', $fingerprint);
    $_SESSION['device_id'] = $deviceId;
    
    return $deviceId;
}

// ================== RELIABLE IP DETECTION ==================
function getClientIP() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    
    $proxyHeaders = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED'
    ];
    
    foreach ($proxyHeaders as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            foreach ($ips as $proxyIp) {
                $proxyIp = trim($proxyIp);
                if (filter_var($proxyIp, FILTER_VALIDATE_IP)) {
                    return $proxyIp;
                }
            }
        }
    }
    
    return $ip;
}

// ================== MAIN EXECUTION ==================
try {
    // Get client info
    $ip = getClientIP();
    $deviceId = getPersistentDeviceId();

    // Handle CORS
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: POST, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type");

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit();
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['status' => 'error', 'message' => 'Only POST method allowed']);
        exit();
    }

    // Validate input
    $input = json_decode(file_get_contents('php://input'), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Invalid JSON input']);
        exit();
    }

    $username = trim($input['username'] ?? '');
    $password = trim($input['password'] ?? '');

    if (empty($username) || empty($password)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Username and password required']);
        exit();
    }

    // Check database connection
    if (!isset($pdo)) {
        throw new PDOException('Database connection failed');
    }

    // Authenticate user
    $stmt = $pdo->prepare("SELECT * FROM student WHERE username = :username OR email = :username");
    $stmt->execute([':username' => $username]);
    $student = $stmt->fetch();

    if (!$student) {
        http_response_code(401);
        echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
        exit();
    }

    // Verify password
    $validPassword = false;
    if (password_verify($password, $student['password'])) {
        $validPassword = true;
    } elseif ($student['password'] === $password) {
        // Upgrade plain text password
        $hashed = password_hash($password, PASSWORD_DEFAULT);
        $pdo->prepare("UPDATE student SET password = ? WHERE username = ?")
           ->execute([$hashed, $student['username']]);
        $validPassword = true;
    }

    if (!$validPassword) {
        http_response_code(401);
        echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
        exit();
    }

    // Log login attempt
    $logStmt = $pdo->prepare("INSERT INTO login 
        (student_name, ip, device_id, enrollment_number, login_time)
        VALUES (?, ?, ?, ?, NOW())");
    $logStmt->execute([
        $student['username'],
        $ip,
        $deviceId,
        $student['enrollment_number']
    ]);

    // Successful response
    echo json_encode([
        'status' => 'success',
        'message' => 'Login successful',
        'student' => [
            'username' => $student['username'],
            'email' => $student['email'],
            'enrollment_number' => $student['enrollment_number'],
            'device_ip' => $ip,
            'device_id' => $deviceId
        ]
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Database error']);
    error_log("Database Error: " . $e->getMessage());
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Server error']);
    error_log("Server Error: " . $e->getMessage());
}
?>