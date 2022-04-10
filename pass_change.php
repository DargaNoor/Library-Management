<?php
    include('session.php');
    include('header.php');

    require_once('config.php');
    $conn = new mysqli("localhost","root","","library_db");

    // Check connection
    if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
    }

    if($_SERVER["REQUEST_METHOD"] == "POST") {  
        $enpass = $_POST['enpass'];
        $renpass = $_POST['renpass'];
        
        if(!strcmp($enpass,$renpass)){
            $sql = "UPDATE `personnel` SET `personnel_password`='".$enpass."'";

            $conn->query($sql);

            echo "<script>alert('Password Updated')</script>";
        }
        else{
            echo "<script>alert('Passwords are not matching')</script>";
        }
    }
?>
<html>
    <body>
        <div class="container" style="padding-top: 20px;">
            <div class="row">
                <div class="col-md-3" style="opacity: 0;"></div>
                <div  class="mainform" class="col-md-6">
                    <h1 style="padding-top: 10px;" align="center">Enter Password Password</h1>
                    <form action="" method="post">
                            <div class="row">
                                <div class="col-md-3"></div>
                                <div class="col-md-3" ><label>Enter Password</label></div>
                                <div class="col-md-6" ><input name="enpass" id="enpass" type="password" class="form-control" required></div>
                            </div>
                        <br>
                            <div class="row">
                                <div class="col-md-3"></div>
                                <div class="col-md-3" ><label>Renter Password</label></div>
                                <div class="col-md-6" ><input name="renpass" id="renpass" type="password" class="form-control" required></div>
                            </div>
                        <br>
                            <div class="row" align="center">
                                <div class="col-md-12" ><input type="submit" class="btn btn-success" name="submit" value="Save"></div>
                            </div>
                    </form>
                </div>
            </div>
            <div class="col-md-3"></div>
        </div>
    </body>
</html>
