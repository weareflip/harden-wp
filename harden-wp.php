<?php
/*
 * Harden Wordpress
 *
 * This plugin patches various probing points for attacks on Wordpress.
 *
 * Plugin Name: Harden Wordpress
 * Description: This plugin patches various probing points for attacks on Wordpress.
 * Version: 1.0.0
 * Author: We Are Flip
 * Author URI: https://weareflip.com.au
*/

require_once('includes/class-csrf-token.php');

@ini_set('session.cookie_httponly', true);
@ini_set('session.cookie_secure', true);
@ini_set('session.use_only_cookies', true);
@ini_set('expose_php', false);


// Add some security related headers
add_action('send_headers', function() {
	$headers = [
		'X-Frame-Options: SAMEORIGIN',
		'Strict-Transport-Security: max-age=31536000'
	];

	foreach ($headers as $header) {
		header($header);
	}
});


// Disable auto-complete on login page inputs, add CSRF protection
add_action('login_form', function () {
	$loginForm = ob_get_contents();
	$loginForm = preg_replace('/(<input[^>]+id="user_login"[^>]+)>/is','$1 autocomplete="off">', $loginForm);
	$loginForm = preg_replace('/(<input[^>]+id="user_pass"[^>]+)>/is','$1 autocomplete="off">', $loginForm);

	ob_get_clean();
	echo $loginForm;
	(new CSRFToken('login'))->field();
	if (isset($_SESSION['form_error'])) {
		echo '<p style="color: red; margin-bottom: 1em">'. $_SESSION['form_error']. '</p>';
		unset($_SESSION['form_error']);
	}
});


// Prevent login if CSRF token fails
add_action('wp_login', function () {
	if (!$_POST) {
		return;
	}

	$tokenClass = new CSRFToken('login');
	
	if ($tokenClass->verifyToken($_POST['csrf_token']) !== true) {
		$_SESSION['form_error'] = 'Session timed out, please try again.';
		wp_logout();
		wp_redirect(wp_login_url());
		die();
	}
}, 10, 2);


// Disable unnecessary endpoints when user is not logged in
add_filter('rest_api_init', function () {
	global $wp;
	$disabled_endpoints = [
		'wp-json/wp/v2/users/?'
	];

	$current_url = add_query_arg(array(), $wp->request);

	if (!is_user_logged_in()) {
		foreach ($disabled_endpoints as $disabled_endpoint) {
			if (preg_match('#^'. $disabled_endpoint. '#is', $current_url)) {
				wp_die('Sorry you must be logged in to access this data.','Access Denied',403);
			}
		}
	}
}, 99);
