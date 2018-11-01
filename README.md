Harden WP
=========

A set of rules to harden up Wordpress. Please ensure HTTPS is set up and valid before installing.

Current functionality:

- Adds CSRF tokens to login form.
- Add `X-Frame-Options` and `Strict-Transport-Security` with sensible defaults to headers.
- Disable the `wp-json/wp/v2/users/` REST endpoint.
