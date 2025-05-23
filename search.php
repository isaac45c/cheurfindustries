<?php
session_start();
require_once './serv/logger.php';

$username = $_SESSION['username'] ?? 'guest'; // If logged in, use username, else "guest"
write_log('Page loaded', $username);

// PHP variables for JS
$isLoggedIn = isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true;
$username = $isLoggedIn ? htmlspecialchars($_SESSION["username"]) : null;
?>
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Spinzone</title>
  <link rel="stylesheet" href="sty/style.css" />
</head>
<body class="light">
  <div id="app">
  <div id="header"></div>
  <div id="content">
    <section id="explore" class="page active">
    </section>
  </div>
  <div id="footer"></div>
</div>


  <script>
    window.isLoggedIn = <?= json_encode($isLoggedIn); ?>;
    window.username = <?= json_encode($username); ?>;
  </script>
  <script src="scr/script.js"></script>
</body>
</html>
