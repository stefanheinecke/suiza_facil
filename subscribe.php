<?php
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = isset($_POST['email']) ? trim($_POST['email']) : '';
    
    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid email']);
        exit;
    }
    
    // Append to file with timestamp
    $file = 'subscribers.txt';
    $timestamp = date('Y-m-d H:i:s');
    $line = $email . ' | ' . $timestamp . "\n";
    
    if (file_put_contents($file, $line, FILE_APPEND | LOCK_EX)) {
        echo json_encode(['success' => true, 'message' => 'Subscribed successfully']);
    } else {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Error saving email']);
    }
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
}
?>
