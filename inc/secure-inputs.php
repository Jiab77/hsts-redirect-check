<?php
// Sanitize external data, never trust the user...
// v2
function sanitize($string, $html = false, $extra = false) {
	if (isset($string) && !empty($string)) {
		// Remove all HTML tags
		if ($html === true) {
			// Convert all possible chars to HTML entites
			$string = htmlentities(strip_tags(trim($string)), ENT_QUOTES, 'UTF-8');
		}
		else {
			// Convert all special chars to HTML entites
			$string = htmlspecialchars(strip_tags(trim($string)), ENT_QUOTES, 'UTF-8');
		}

		// Extra clean
		if ($extra === true) {
			// Potentialy dangerous items
			$danger = ["'", '"', '`', '../', '..\\', 'javascript:', 'script'];
			// Safe replacement
			$replace = '';
			// Cleaning
			$string = str_replace($danger, $replace, $string);
		}

		return $string;
	}
	return false;
}

// Wrapper for sanitize function
function cleanEntry(&$value) {
	$value = sanitize($value, true, true);
}

// Clean every possible user inputs
array_walk_recursive($_POST, 'cleanEntry');
array_walk_recursive($_GET, 'cleanEntry');
array_walk_recursive($_REQUEST, 'cleanEntry');