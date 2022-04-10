<?php
    ini_set('SMTP','myserver');
    ini_set('smtp_port',25);
    if($_SERVER["REQUEST_METHOD"] == "POST") {   
        $conn = new mysqli("localhost","root","","library_db");
  
        $loginUser = $_POST['username'];
        
        $query = $conn->query("SELECT `email` FROM `personnel` WHERE `personnel_login`='".$loginUser."';");

        if (!$query) {
            echo "<script type=\"text/javascript\">alert('Enter correct credentials');window.location.href = \"http://localhost/library-management-system-master/resetpwd.php\";</script>";
        }
        
        $result = $query->fetch_assoc();
        $mail=$result["email"];
       
        if(!($result)) {
            echo "<script type=\"text/javascript\">alert('Enter correct credentials');window.location.href = \"http://localhost/library-management-system-master/resetpwd.php\";</script>";
        }
        $headers  = "MIME-Version: 1.0" . "\r\n";
        $headers .= "Content-type: text/html; charset=iso-8859-1" . "\r\n";
        $headers  .= "From: gvsairoshan0@gmail.com" . "\r\n";
        mail($mail,"Verification Code","3456",$headers);
        header("http://localhost/library-management-system-master/mail.php");
    }
                
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Library Management System</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="assets/css/login.css">
    <link rel="stylesheet" href="assets/css/gradients.css">
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <script src="assets/js/jquery.js"></script>   
    <script src="assets/js/bootstrap.js"></script>
</head>

<body>
    <div class="login-group absolute-center night-fade-gradient">
        <h5 class="text-center">Welcome</h5>
        </br>
        <form action = "" method = "post">
            <div class="form-group">
                <input name="username" type="username" class="form-control" id="name_input" required placeholder="Enter username">
            </div>
            <div class="form-group row">

            </div>
            <input type="submit" class="btn btn-light btn-block" value="Login"/><br />
        </form>
    </div>
</body>
</html>