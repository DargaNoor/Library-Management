<!--
    Header element
-->

<?php
    if(!defined('DirectAccess')) {
        header("location:index.php");
    }
?>

<head>
    <link rel="stylesheet" href="assets/css/header.css">
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <script src="assets/js/jquery.js"></script>
</head>

<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-secondary header justify-content-between">   
        <nav class="navbar navbar-light bg-light">
            <a class="navbar-brand" href="index.php">
                <img src="assets/images/logo.png" height="40" alt="">
            </a>
        </nav>
        <div class="navbar-collapse">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item active">
                    <a class="nav-link" href="index.php" style="color:white">Home</a>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" style="color:white">Actions</a>
                    <div class="dropdown-menu">
                        <a class="dropdown-item" href="books.php">Manage Books</a>
                        <a class="dropdown-item" href="borrows.php">Manage Loans</a>
                        <a class="dropdown-item" href="members.php">Manage Members</a>
                    </div>
                </li>
                <li class="nav-item active">
                    <a class="nav-link" href="pass_change.php" style="color:white">Change Password</a>
                </li>
                <li class="navbar-text" style="color:white">
                    Welcome, <?php echo $_SESSION['loginUser']; ?>
                </li>
            </ul>
        </div>
        <a type="button" class="btn btn-dark" href="logout.php">Log out</a>
    </nav>
</body>