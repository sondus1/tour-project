<?php

$host = "localhost";
$user = "root";
$pass = "";
$dbname = "explore_more";

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

session_start();

function register_user($conn, $name, $email, $phone, $password) {

    $check = $conn->prepare("SELECT id FROM users WHERE email=?");
    $check->bind_param("s", $email);
    $check->execute();
    $check->store_result();

    if ($check->num_rows > 0) {
        return "EMAIL_EXISTS";
    }

    $hashed = password_hash($password, PASSWORD_DEFAULT);

    $insert = $conn->prepare("INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)");
    $insert->bind_param("ssss", $name, $email, $phone, $hashed);

    if ($insert->execute()) {
        return "REGISTER_SUCCESS";
    }

    return "REGISTER_FAILED";
}

function login_user($conn, $email, $password) {

    $query = $conn->prepare("SELECT id, name, password FROM users WHERE email=? LIMIT 1");
    $query->bind_param("s", $email);
    $query->execute();
    $result = $query->get_result();

    if ($result->num_rows != 1) {
        return "EMAIL_NOT_FOUND";
    }

    $row = $result->fetch_assoc();

    if (password_verify($password, $row['password'])) {
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['user_name'] = $row['name'];
        return "LOGIN_SUCCESS";
    }

    return "WRONG_PASSWORD";
}

if (isset($_POST['action']) && $_POST['action'] === "register") {

    $name     = $_POST['name'] ?? "";
    $email    = $_POST['email'] ?? "";
    $phone    = $_POST['phone'] ?? "";
    $password = $_POST['password'] ?? "";

    $result = register_user($conn, $name, $email, $phone, $password);

    echo $result;
    exit;
}


if (isset($_POST['action']) && $_POST['action'] === "login") {

    $email    = $_POST['email'] ?? "";
    $password = $_POST['password'] ?? "";

    $result = login_user($conn, $email, $password);

    echo $result;
    exit;
}
?>
