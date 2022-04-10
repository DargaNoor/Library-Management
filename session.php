<?php
   include('config.php');
   session_start();

   define('DirectAccess', TRUE);
   
   if(!isset($_SESSION['loginUser'])){
      header("location:login.php");
      die();
   }
?>