<?php

/**
 * @file
 * Sample OAuth2 Library Mongo DB Implementation.
 * 
 */

require_once __DIR__ . '/../../../../lib/OAuth2.php';
require_once __DIR__ . '/../../../../lib/IOAuth2Storage.php';
require_once __DIR__ . '/../../../../lib/IOAuth2GrantCode.php';
require_once __DIR__ . '/../../../../lib/IOAuth2GrantClient.php';
require_once __DIR__ . '/../../../../lib/IOAuth2GrantUser.php';
require_once __DIR__ . '/../../../../lib/IOAuth2RefreshTokens.php';

/**
 * 
 * Mongo storage engine for the OAuth2 Library.
 */
class OAuth2StorageMongo implements IOAuth2GrantCode, IOAuth2RefreshTokens, IOAuth2GrantClient, IOAuth2GrantUser {
	
	/**
	 * Change this to something unique for your system
	 * @var string
	 */
	const SALT = 'CHANGE_ME!';
	
	const CONNECTION = 'mongodb://user:pass@mongoserver/mydb';
//	const CONNECTION = 'mongodb://user:pass@localhost/mydb';
	const DB = 'mydb';
	
	/**
	 * @var Mongo
	 */
	private $db;

	/**
	 * Implements OAuth2::__construct().
	 */
	public function __construct() {
		
		$mongo = new Mongo(self::CONNECTION);
		$this->db = $mongo->selectDB(self::DB);
	}

	/**
	 * Release DB connection during destruct.
	 */
	function __destruct() {
		$this->db = NULL; // Release db connection
	}

	/**
	 * Little helper function to add a new client to the database.
	 *
	 * @param $client_id
	 * Client identifier to be stored.
	 * @param $client_secret
	 * Client secret to be stored.
	 * @param $redirect_uri
	 * Redirect URI to be stored.
	 * @param $grant_types
	 * Supported grant types
	 */
	public function addClient($client_id, $client_secret, $redirect_uri, $grant_types) {
		$client = array("_id" => $client_id, "pw" => $this->hash($client_secret, $client_id), "redirect_uri" => $redirect_uri);
		if ($grant_types)
			$client['grant_types'] = explode(',', $grant_types);
		$this->db->clients->save($client);
	}

	/**
	 * Little helper function to add a new user to the database.
	 *
	 * @param $username
	 * Username identifier to be stored.
	 * @param $password
	 * Password to be stored.
	 */
	public function addUser($username, $password) {
		$user = array("_id" => $username, "pw" => $this->hash($password, $username));
		$this->db->users->save($user);
	}

	/**
	 * Implements IOAuth2Storage::checkClientCredentials().
	 *
	 */
	public function checkClientCredentials($client_id, $client_secret = NULL) {
		$client = $this->db->clients->findOne(array("_id" => $client_id), array("pw"));
		return $this->checkPassword($client['pw'], $client_secret, $client_id);
	}

	/**
	 * Implements IOAuth2Storage::getRedirectUri().
	 */
	public function getClientDetails($client_id) {
		$result = $this->db->clients->findOne(array("_id" => $client_id), array("redirect_uri"));
		return $result;
	}

	/**
	 * Implements IOAuth2Storage::getAccessToken().
	 */
	public function getAccessToken($oauth_token) {
		return $this->db->tokens->findOne(array("_id" => $oauth_token));
	}

	/**
	 * Implements IOAuth2Storage::setAccessToken().
	 */
	public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = NULL) {
		$this->db->tokens->insert(array("_id" => $oauth_token, "client_id" => $client_id, "user_id" => $user_id, "expires" => $expires, "scope" => $scope));
	}

	/**
	 * @see IOAuth2RefreshTokens::getRefreshToken()
	 */
	public function getRefreshToken($refresh_token) {
		return $this->db->refresh_tokens->findOne(array("_id" => $refresh_token));
	}

	/**
	 * @see IOAuth2RefreshTokens::setRefreshToken()
	 */
	public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = NULL) {
		$this->db->refresh_tokens->insert(array("_id" => $refresh_token, "client_id" => $client_id, "user_id" => $user_id, "expires" => $expires, "scope" => $scope));
	}

	/**
	 * @see IOAuth2RefreshTokens::unsetRefreshToken()
	 */
	public function unsetRefreshToken($refresh_token) {
		$this->db->refresh_tokens->remove(array("_id" => $refresh_token));
	}

	/**
	 * @see IOAuth2GrantClient::checkClientCredentialsGrant()
	 */
	public function checkClientCredentialsGrant($client_id, $client_secret) {
		$client = $this->db->clients->findOne(array('_id' => $client_id), array('pw'));

		return $this->checkPassword($client['pw'], $client_secret, $client_id);
	}

	/**
	 * @see IOAuth2GrantUser::checkUserCredentials()
	 */
	public function checkUserCredentials($client_id, $username, $password) {
		$user = $this->db->users->findOne(array("_id" => $username));
		if (!$this->checkPassword($user['pw'], $password, $username))
			return false;

		// we could check a users collection, blah blah, but this will suffice for now
		$user['user_id'] = $user['_id'];
		return $user;
	}


	/**
	 * Implements IOAuth2Storage::getAuthCode().
	 */
	public function getAuthCode($code) {
		$stored_code = $this->db->auth_codes->findOne(array("_id" => $code));
		return $stored_code !== NULL ? $stored_code : FALSE;
	}

	/**
	 * Implements IOAuth2Storage::setAuthCode().
	 */
	public function setAuthCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = NULL) {
		$this->db->auth_codes->insert(array("_id" => $code, "client_id" => $client_id, "redirect_uri" => $redirect_uri, "user_id" => $user_id, "expires" => $expires, "scope" => $scope));
	}

	/**
	 * @see IOAuth2Storage::checkRestrictedGrantType()
	 */
	public function checkRestrictedGrantType($client_id, $grant_type) {
		$client = $this->db->clients->findOne(array('_id' => $client_id), array('grant_types'));

		// if no grant types are specified, assume all are valid
		if (!isset($client['grant_types']))
			return TRUE;

		// return true iff the grant_type is amongst those listed
		return in_array($grant_type, $client['grant_types']);
	}

	/**
	 * Change/override this to whatever your own password hashing method is.
	 * 
	 * @param string $secret
	 * @return string
	 */
	protected function hash($client_secret, $client_id) {
//		return hash('sha1', $client_id . $client_secret . self::SALT);
		return hash('blowfish', $client_id . $client_secret . self::SALT);
	}

	/**
	 * Checks the password.
	 * Override this if you need to
	 * 
	 * @param string $client_id
	 * @param string $client_secret
	 * @param string $actualPassword
	 */
	protected function checkPassword($try, $client_secret, $client_id) {
		return $try == $this->hash($client_secret, $client_id);
	}
}
