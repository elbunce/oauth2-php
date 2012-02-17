<?php

/**
 * @file
 * Sample client add script.
 *
 * Obviously not production-ready code, just simple and to the point.
 */

require_once "lib/OAuth2StorageMongo.php";

if ($_POST && isset($_POST["client_id"]) && isset($_POST["client_secret"]) && isset($_POST["redirect_uri"])) {
	$oauth = new OAuth2StorageMongo();
	$oauth->addClient($_POST["client_id"], $_POST["client_secret"], $_POST["redirect_uri"], $_POST["grant_types"]);
}

?>

<html>
<head>
Add Client
</head>
<body>
<form method="post" action="addclient.php">
<p><label for="client_id">Client ID:</label> <input type="text" name="client_id" id="client_id" /></p>
<p><label for="client_secret">Client Secret (password/key):</label> <input type="text" name="client_secret" id="client_secret" /></p>
<p><label for="redirect_uri">Redirect URI:</label> <input type="text" name="redirect_uri" id="redirect_uri" size='80' /></p>
<p><label for="grant_types">Grant Types:</label> <input type="text" name="grant_types" id="grant_types" value="authorization_code,refresh_token,extensions"/ size='80'></p>
<input type="submit" value="Submit" /></form>
</body>
</html>
