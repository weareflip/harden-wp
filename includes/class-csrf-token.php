<?php

class CSRFToken {
	/**
	 * CSRF Token string.
	 *
	 * @var string
	 */
	public $token;

	/**
	 * Unique-ish hash based off IP address.
	 *
	 * @var string
	 */
	public $uid;

	public $action;

	/**
	 * CSRFToken constructor.
	 *
	 * @param string $action
	 */
	public function __construct($action = '')
	{
		if (session_status() == PHP_SESSION_NONE) {
			session_start();
		}
		
		$this->uid = $uid = $this->generateUID();
		$this->action = $action;
	}

	/**
	 * Generate a unique hash for the user (by IP/User email).
	 *
	 * @return false|string
	 */
	private function generateUID()
	{
		$user = wp_get_current_user();

		$UIDString = sprintf('%s|%s',
			$_SERVER['REMOTE_ADDR'],
			isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : ''
		);

		return wp_hash($UIDString, 'nonce');
	}

	/**
	 * Generate a CSRF token.
	 *
	 * @param string $action
	 *
	 * @return string
	 */
	public function generateToken()
	{
		$expiry = time() + (15*60);   // Expire in 15 minutes
		$token = $this->makeHash($expiry, $this->uid, $this->action);

		// Store in session for verification
		$_SESSION[$this->uid. '_expiry'] = $expiry;

		return $token;
	}

	/**
	 * Verify a CSRF token.
	 *
	 * @param string $token
	 *
	 * @return string
	 */
	public function verifyToken($token)
	{
		$expiry = $_SESSION[$this->uid. '_expiry'];

		// Invalidate if expired
		if (time() > $expiry) {
			return false;
		}

		// Set status to true if CSRF has not expired and matches session
		$verified = ($token === $this->makeHash($expiry, $this->uid, $this->action));
		unset($_SESSION[$this->uid. '_expiry']);

		return $verified;
	}

	private function makeHash($expiry, $uid, $action)
	{
		$unencryptedToken = sprintf('%s|%s|%s', $expiry, $uid, $action);
		return hash_hmac('sha256', $unencryptedToken, wp_salt('nonce'));
	}

	/**
	 * Generate a CSRF token.
	 *
	 * @param string $name
	 * @param bool $echo
	 *
	 * @return string
	 */
	public function field($name = 'csrf_token', $echo = true)
	{
		$field = sprintf('<input type="hidden" name="%s" value="%s">', $name, $this->generateToken());

		if ($echo) {
			echo $field;
			return '';
		}

		return $field;
	}
}
