<?php

/**
 * @file
 * Sample user add script.
 *
 * Obviously not production-ready code, just simple and to the point.
 */

require_once "lib/OAuth2StorageMongo.php";

if ($_POST && isset($_POST["user_name"]) && isset($_POST["user_secret"])) {
	$oauth = new OAuth2StorageMongo();
	$oauth->addUser($_POST["user_name"], $_POST["user_secret"]);
}

?>

<html>
<head>
Add User
</head>
<body>
<form method="post" action="adduser.php">
<p><label for="client_id">Usernae:</label> <input type="text" name="user_name" id="user_name" /></p>
<p><label for="client_secret">User Secret (password/key):</label> <input type="text" name="user_secret" id="user_secret" /></p>
<input type="submit" value="Submit" /></form>
</body>
</html>
