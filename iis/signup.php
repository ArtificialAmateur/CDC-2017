<?php
	ini_set('display_errors',1);
	
	$username = $password = $domain = $address = $phone = "";
	
	if(isset($_POST['username']) && strlen($_POST['username']) <= 100) {
		$username = stripslashes(strip_tags(trim($_POST['username'])));
	}

	if(isset($_POST['password']) && strlen($_POST['password']) <= 100) {
		$password = stripslashes(strip_tags(trim($_POST['password'])));
	}

	if(isset($_POST['domain']) && strlen($_POST['domain']) <= 100) {
		$domain = stripslashes(strip_tags(trim($_POST['domain'])));
	}
	
	if(isset($_POST['address']) && strlen($_POST['address']) <= 100) {
		$address = stripslashes(strip_tags(trim($_POST['address'])));
	}
	
	if(isset($_POST['phone']) && strlen($_POST['phone']) <= 100) {
		$phone = stripslashes(strip_tags(trim($_POST['phone'])));
	}
	
	//Create AD user
	$cmd = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Noninteractive -command ". C:\inetpub\wwwroot\adduser.ps1 \'' . $username .  '\' \''  . $password . '\' \'' . $address . '\'  \'' . $phone . '\';"';
	if($a=exec($cmd)) {
		echo "ok";
	}
	
	//Create DNS record
	$cmd = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Noninteractive -command ". C:\inetpub\wwwroot\setdns.ps1 \''  . $username . '\';"';
	if($a=exec($cmd)) {
		echo "ok";
	}
		
 	//Create MySQL user
	$db = $username;
	$conn  = mysql_connect('192.168.0.10', 'creator', 'J_Magill');
	mysql_query("CREATE USER '$username'@'localhost' IDENTIFIED BY '$password';");
	mysql_query("CREATE USER '$username'@'%' IDENTIFIED BY '$password';");
	mysql_query("GRANT ALL ON $db.* TO '$username'@'localhost' IDENTIFIED BY '$password';");
	mysql_query("GRANT ALL ON $db.* TO '$username'@'%' IDENTIFIED BY '$password';");
	
	//Create MySQL database
	$retval = mysql_query("CREATE DATABASE $db;");
	if(! $retval){
		die("Could not create database: " . mysql_error());
	} else {
		echo "Database $db created successfully\n";
	}
	
	mysql_close($conn);
?>