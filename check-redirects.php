<?php
// Debug
error_reporting(E_ALL);
ini_set('display_errors', false);
ini_set('log_errors', true);
ini_set('error_log', sys_get_temp_dir() . '/php.errors.log');
ini_set('log_errors_max_len', 4096);

// Dependecies
require_once __DIR__ . '/inc/secure-inputs.php';
require_once __DIR__ . '/inc/framework.php';

// Global config
$cache_timeout = 60;
$query_timeout = 10;
$max_redirects = 5;

// Init cache
$f3->set('CACHE','folder=' . sys_get_temp_dir() . '/');

// Required functions
function extract_domain($parsed_domain, &$parts = []) {
	$parts[] = array_pop($parsed_domain);
	if (count($parts) <= 1) {
		extract_domain($parsed_domain, $parts);
	}
	return $parts;
}
function extract_subdomains($parsed_domain, &$parts = []) {
	$parts[] = array_pop($parsed_domain);
	$cleaned_parts = [];
	if (count($parsed_domain) > 0) {
		extract_subdomains($parsed_domain, $parts);
	}
	if ($parts > 2) {
		unset($parts[0]);
		unset($parts[1]);
		foreach ($parts as $part) {
			$cleaned_parts[] = $part;
		}
		// $parts = array_slice($parts, 2);
		return $cleaned_parts;
	}
	else {
		return false;
	}
}
function get_head($host, $context_options = false) {
	global $max_redirects;

	// Create Web instance
	$web = \Web::instance();
	$options = [
		'http' => ['method'=>'HEAD', 'max_redirects' => $max_redirects],
		'https' => ['method'=>'HEAD', 'max_redirects' => $max_redirects]
	];
	if ($context_options !== false && is_array($context_options)) {
		foreach ($context_options as $ctx_option) {
			$options['http'][] = $ctx_option;
		}
	}
	$headers = $web->request('http://' . $host, $options)['headers'];
	return $headers;
}
function get_loading_time() {
	return number_format(microtime(true) - $_SERVER["REQUEST_TIME_FLOAT"], 4);
}

// Init processing
if (isset($_GET['q']) && !empty($_GET['q'])) {
	// Local config
	$log = '';
	$table = '';
	$host = $_GET['q'];
	$parsed_domain = explode('.', $host);

	// Data extraction
	extract_domain($parsed_domain, $domain_parts);
	extract_subdomains($parsed_domain, $sub_domain_parts);

	// Log processing
	$log  = 'Given [' . $host . ']' . PHP_EOL;
	$log .= 'Parsed:' . PHP_EOL;
	$log .= print_r($parsed_domain, true);

	// Check if sub domain does exists
	$has_subdomain = (count($parsed_domain) > 2);
	if ($has_subdomain) {
		$log .= PHP_EOL . 'Domain only:' . PHP_EOL;
		$log .= print_r($domain_parts, true);
		$log .= PHP_EOL . 'Sub Domains only:' . PHP_EOL;
		$log .= print_r($sub_domain_parts, true);
	}

	// Create inital HTML table code
	$table  = '<table>' . PHP_EOL;
	$table .= '<thead>' . PHP_EOL;
	$table .= '<tr>' . PHP_EOL;
	$table .= '<th>Host</th>' . PHP_EOL;
	$table .= '<th>Result</th>' . PHP_EOL;
	$table .= '</tr>' . PHP_EOL;
	$table .= '</thead>' . PHP_EOL;
	$table .= '<tbody>' . PHP_EOL;

	// Process all possible sub domains to the main domain
	if ($has_subdomain) {
		// Reconstruct domain name
		$domain_parts = array_reverse($domain_parts);
		$domain = implode('.', $domain_parts);
		$targets = [$domain];

		// Reconstruct sub domain names
		$passes = 0; // Init passes counter
		for ($i = 1; $i <= count($sub_domain_parts); $i++) {
			// Add found sub domains as targets
			$sub_domain = $sub_domain_parts[$i] . ($passes > 1 ? '.' . $sub_domain : '');

			// Avoid to add '.domain' as targets
			if ($sub_domain . '.' . $domain !== '.' . $domain) {
				$target_sub_domain = $sub_domain . '.' . $domain;
				$targets[] = $target_sub_domain;
			}

			// Increment passes counter
			$passes++;
		}

		// Add the given host as last sub domain as target
		if (!isset($sub_domain) && $has_subdomain) {
			$sub_domain = $host;
		}
		$targets[] = $host;

		// Process all created targets
		$index = 0;
		foreach ($targets as $target) {
			$log .= PHP_EOL . 'Testing [' . $target . ']' . PHP_EOL;
			$valid_target = checkdnsrr($target, 'A');
			$log .= ($valid_target ? 'Domain is valid.' : 'No website was found on this domain.') . PHP_EOL;

			if ($valid_target) {
				// Add new line and cell to the HTML table
				$table .= '<tr>' . PHP_EOL;
				$table .= '<td>' . $target . '</td>' . PHP_EOL;

				$f3->set('domain_records', @dns_get_record($target, DNS_ANY, $authns, $addtl), $cache_timeout);
				if (!is_array($domain_records)) {
					$f3->set('domain_records', @dns_get_record($target, DNS_A, $authns, $addtl), $cache_timeout);
					$log .= PHP_EOL. 'Using [DNS_A] query type.' . PHP_EOL;
				}
				else {
					$log .= PHP_EOL. 'Using [DNS_ANY] query type.' . PHP_EOL;
				}
				$domain_records = $f3->get('domain_records');
				$log .= print_r($domain_records, true);
				if ($authns) {
					$log .= print_r($authns, true);
				}
				if ($addtl) {
					$log .= print_r($addtl, true);
				}

				if ($f3->set('query_headers', get_head($target, ['timeout' => $query_timeout]), $cache_timeout)) {
					$hsts_found = false;
					$headers = $f3->get('query_headers');
					$log .= PHP_EOL . 'Collected headers:' . PHP_EOL;
					$log .= print_r($headers, true);

					for ($i=0; $i < count($headers)-1; $i++) {
						if (stripos($headers[$i], 'Strict-Transport-Security') !== false) {
							$hsts_found = true;

							// Reading headers for subdomain
							if ($index >= 1) {
								$log .= PHP_EOL . 'HSTS detected on subdomain [' . $target . '] !' . PHP_EOL;

								if (stripos($headers[$i], 'includeSubDomains;') !== false) {
									// Add new cell to the HTML table
									$table .= '<td><strong style="color: red;">HSTS detected on subdomain [' . $target . '] !</strong><br>';
									$log .= 'This subdomain is also protected. Redirections may work or not.' . PHP_EOL;
									$table .= 'This subdomain is also protected. Redirections may work or not.';
								}
								else {
									// Add new cell to the HTML table
									$table .= '<td><strong style="color: blue;">HSTS detected on subdomain [' . $target . '] !</strong><br>';
									$log .= 'This subdomains is not protected. Redirections might works.' . PHP_EOL;
									$table .= 'This subdomains is not protected. Redirections might works.';
								}

								// Closing table cell
								$table .= '</td>' . PHP_EOL;
							}

							// Reading headers for domain
							else {
								$log .= PHP_EOL . 'HSTS detected on domain [' . $target . '] !' . PHP_EOL;

								if (stripos($headers[$i], 'includeSubDomains;') !== false) {
									// Add new cell to the HTML table
									$table .= '<td><strong style="color: orange;">HSTS detected on domain [' . $target . '] !</strong><br>';
									$log .= 'Subdomains are also protected. Redirections might be impacted.' . PHP_EOL;
									$table .= 'Subdomains are also protected. Redirections might be impacted.';
								}
								else {
									// Add new cell to the HTML table
									$table .= '<td><strong style="color: blue;">HSTS detected on domain [' . $target . '] !</strong><br>';
									$log .= 'Subdomains are not protected. Redirections might not be impacted.' . PHP_EOL;
									$table .= 'Subdomains are not protected. Redirections might not be impacted.';
								}

								// Closing table cell
								$table .= '</td>' . PHP_EOL;
							}

							break; // Exit the loop
						}
					}

					if ($hsts_found === false) {
						// Reading headers for subdomain
						if ($target === $sub_domain) {
							$log .= PHP_EOL . 'HSTS not detected on subdomain [' . $target . '].' . PHP_EOL;
							$log .= 'This subdomains is not protected. Redirections might work.' . PHP_EOL;

							// Add new cell to the HTML table
							$table .= '<td><strong style="color: green;">HSTS not detected on subdomain [' . $target . '].</strong><br>This subdomains is not protected. Redirections might work.</td>' . PHP_EOL;
						}

						// Reading headers for domain
						else {
							$log .= PHP_EOL . 'HSTS not detected on domain [' . $target . '].' . PHP_EOL;
							$log .= 'Subdomains are not protected. Redirections might not be impacted.' . PHP_EOL;

							// Add new cell to the HTML table
							$table .= '<td><strong style="color: green;">HSTS not detected on domain [' . $target . '].</strong><br>Subdomains are not protected. Redirections might not be impacted.</td>' . PHP_EOL;
						}
					}
				}

				// Empty returned headers
				else {
					$log .= PHP_EOL . 'Failed to get HTTP headers.' . PHP_EOL;
					$table .= '<td><strong style="color: red;">Failed to get HTTP headers.</strong></td>' . PHP_EOL;
				}

				// Closing new line
				$table .= '</tr>' . PHP_EOL;
			}
			else {
				// Add new line and cell to the HTML table
				$table .= '<tr>' . PHP_EOL;
				$table .= '<td>' . $target . '</td>' . PHP_EOL;
				$table .= '<td><strong style="color: blue;">No website was found on this domain.</strong></td>' . PHP_EOL;
				$table .= '</tr>' . PHP_EOL;
			}

			// Increment loop counter
			$index++;
		}
	}

	// Process the main domain only
	else {
		$valid_target = checkdnsrr($host, 'A');
		$log .= ($valid_target ? 'Domain is valid.' : 'No website was found on this domain.') . PHP_EOL;

		if ($valid_target) {
			// Add new line and cell to the HTML table
			$table .= '<tr>' . PHP_EOL;
			$table .= '<td>' . $host . '</td>' . PHP_EOL;

			$f3->set('domain_records', @dns_get_record($host, DNS_ANY, $authns, $addtl), $cache_timeout);
			if (!is_array($domain_records)) {
				$f3->set('domain_records', @dns_get_record($host, DNS_A, $authns, $addtl), $cache_timeout);
				$log .= PHP_EOL. 'Using [DNS_A] query type.' . PHP_EOL;
			}
			else {
				$log .= PHP_EOL. 'Using [DNS_ANY] query type.' . PHP_EOL;
			}
			$domain_records = $f3->get('domain_records');
			$log .= print_r($domain_records, true);
			if ($authns) {
				$log .= print_r($authns, true);
			}
			if ($addtl) {
				$log .= print_r($addtl, true);
			}

			if ($f3->set('query_headers', get_head($host, ['timeout' => $query_timeout]), $cache_timeout)) {
				$hsts_found = false;
				$headers = $f3->get('query_headers');
				$log .= PHP_EOL . 'Collected headers:' . PHP_EOL;
				$log .= print_r($headers, true);

				for ($i=0; $i < count($headers)-1; $i++) { 
					if (stripos($headers[$i], 'Strict-Transport-Security') !== false) {
						$hsts_found = true;

						$log .= PHP_EOL . 'HSTS detected on domain [' . $host . '] !' . PHP_EOL;

						if (stripos($headers[$i], 'includeSubDomains') !== false) {
							// Add new cell to the HTML table
							$table .= '<td><strong style="color: red;">HSTS detected on domain [' . $host . '] !</strong><br>';
							$log .= 'Subdomains are also protected. Redirections might be impacted.' . PHP_EOL;
							$table .= 'Subdomains are also protected. Redirections might be impacted.' . PHP_EOL;
						}
						else {
							// Add new cell to the HTML table
							$table .= '<td><strong style="color: orange;">HSTS detected on domain [' . $host . '] !</strong><br>';
							$log .= 'Subdomains are not protected. Redirections might not be impacted.' . PHP_EOL;
							$table .= 'Subdomains are not protected. Redirections might not be impacted.' . PHP_EOL;
						}

						// Closing table cell
						$table .= '</td>' . PHP_EOL;

						break; // Exit the loop
					}
				}

				if ($hsts_found === false) {
					$log .= PHP_EOL . 'HSTS not detected on domain [' . $host . '].' . PHP_EOL;
					$log .= 'Subdomains are not protected. Redirections might not be impacted.' . PHP_EOL;

					// Add new cell to the HTML table
					$table .= '<td><strong style="color: green;">HSTS not detected on domain [' . $host . '].</strong><br>Subdomains are not protected. Redirections might not be impacted.</td>' . PHP_EOL;
				}
			}

			// Empty returned headers
			else {
				$log .= PHP_EOL . 'Failed to get HTTP headers.' . PHP_EOL;
				$table .= '<td><strong style="color: red;">Failed to get HTTP headers.</strong></td>' . PHP_EOL;
			}

			// Closing new line
			$table .= '</tr>' . PHP_EOL;
		}
		else {
			// Add new line and cell to the HTML table
			$table .= '<tr>' . PHP_EOL;
			$table .= '<td>' . $host . '</td>' . PHP_EOL;
			$table .= '<td><strong style="color: blue;">No website was found on this domain.</strong></td>' . PHP_EOL;
			$table .= '</tr>' . PHP_EOL;
		}
	}

	// Closing HTML table
	$table .= '</tbody>' . PHP_EOL;
	$table .= '</table>' . PHP_EOL;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<!-- Default Metas -->
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta http-equiv="x-dns-prefetch-control" content="on">
	
	<!-- Mobile Support -->
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	
	<!-- SEO -->
	<meta name="author" content="Jonathan Barda (@Jiab77)">
	
	<!-- Robots Metas -->
	<meta name="robots" content="noindex,nofollow,nosnippet,noodp,noarchive,noimageindex">
	<meta name="google" content="nositelinkssearchbox">

	<!-- Pre-Things -->
	<link rel="dns-prefetch" href="//cdnjs.cloudflare.com">
	<link rel="dns-prefetch" href="//fonts.googleapis.com">
	<link rel="dns-prefetch" href="//fonts.gstatic.com">
	<link rel="dns-prefetch" href="//www.google.com">

	<!-- Import Google Icon Font -->
	<link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons" media="all">

	<!-- Import FontAwesome Icon Font -->
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.9.0/css/fontawesome.min.css" media="all">
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.9.0/css/brands.min.css" media="all">

	<!-- Import Normalizecss -->
	<link type="text/css" rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css" media="all">
	
	<!-- Import Materialize -->
	<link type="text/css" rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/0.100.2/css/materialize.min.css" media="screen,projection">
	
	<!-- Import Style -->
	<link type="text/css" rel="stylesheet" href="res/main.css" media="all">
	<title>HSTS Redirection Check</title>
</head>
<body>
	<header>
		<div class="navbar-fixed">
			<nav class="grey darken-4">
				<div class="nav-wrapper">
					<a class="brand-logo" href="#!"><i class="material-icons hide-on-med-and-down">public</i>HSTS Redirection Check</a>
					<ul class="right hide-on-med-and-down">
						<li><a href="#!" class="tooltipped" data-position="bottom" data-tooltip="Refresh" onclick="window.location.reload();"><i class="material-icons">refresh</i></a></li>
						<li><a href="https://github.com/Jiab77/hsts-redirect-check" class="tooltipped" data-position="bottom" data-tooltip="Fork me on github" target="_blank"><i class="fab fa-github-alt fa-anim" onmouseover="$(this).addClass('fa-2x');" onmouseout="$(this).removeClass('fa-2x');"></i></a></li>
					</ul>
				</div>
			</nav>
		</div>
	</header>
	<main>
		<div class="container">
			<h3 class="center-align">HSTS Redirection Check</h3>
			<div class="row">
				<form class="col s12" id="check-form" method="GET">
					<div class="row">
						<div class="input-field col s12">
							<input type="text" id="check_host" name="q" class="validate" placeholder="Enter hostname (eg: example.com, without protocol.)" value="<?php echo (isset($_GET['q']) ? $_GET['q'] : ''); ?>" required autofocus>
							<label for="check_host">Host</label>
						</div>
						<div class="input-field col s12 center-align">
							<input type="submit" id="submit_host" class="btn" value="Check">
						</div>
					</div>
				</form>
			</div>

			<?php if (isset($_GET['q']) && !empty($_GET['q'])): ?>
			<div class="row">
				<div class="col s12">
					<?php if (isset($table) && !empty($table)) { echo $table; } ?>
				</div>
			</div>
			<div class="row">
				<div class="col s12 center-align">
					<a href="#!" onclick="$('#details').toggleClass('hide');">Show / Hide<br>Details</a>
				</div>
			</div>
			<div class="row hide" id="details">
				<div class="col s12">
					<fieldset>
						<legend>Details</legend>
						<pre style="height: 250px; max-width: 1280px; overflow: auto; margin-bottom: 0;"><?php
						if (isset($log) && !empty($log)) {
							echo $log;
						}
						?></pre>
					</fieldset>
				</div>
			</div>
			<?php endif; ?>

		</div>
	</main>
	<footer class="page-footer grey darken-3">
		<div class="container">
			<div class="row">
				<div class="col l8 s12">
					<h5 class="white-text">Loading time</h5>
					<p class="grey-text text-lighten-4"><?php echo 'Generated in: ' . get_loading_time() . ' seconds'; ?></p>
				</div>
				<div class="col l2 offset-l2 s12">
					<h5 class="white-text">Links</h5>
					<ul>
						<li><a class="grey-text text-lighten-3" href="https://github.com/Jiab77/hsts-redirect-check" target="_blank"><i class="material-icons tiny">code</i> Project</a></li>
						<li><a class="grey-text text-lighten-3" href="https://github.com/Jiab77" target="_blank"><i class="fab fa-github"></i> Profile</a></li>
						<li><a class="grey-text text-lighten-3" href="https://gist.github.com/Jiab77" target="_blank"><i class="material-icons tiny">library_books</i> Gists</a></li>
						<li><a class="grey-text text-lighten-3" href="https://twitter.com/jiab77" rel="noreferrer" target="_blank"><i class="fab fa-twitter"></i> Twitter</a></li>
					</ul>
				</div>
			</div>
		</div>
		<div class="footer-copyright grey darken-4">
			<div class="container">
				<?php echo '&copy; ' . date("Y") . ' &ndash; <a href="https://twitter.com/jiab77" rel="noreferrer" target="_blank">Jiab77</a>' . PHP_EOL; ?>
				<span class="grey-text text-lighten-4 right">Made with <span class="pink-text text-accent-3 tooltipped" data-position="top" data-tooltip="love" style="cursor: default;"><i class="material-icons">favorite</i></span> of <span class="white-text tooltipped" data-position="top" data-tooltip="code" style="cursor: default;"><i class="material-icons">code</i></span> and <span class="brown-text text-accent-3 tooltipped" data-position="top" data-tooltip="coffee" style="cursor: default;"><i class="material-icons">local_cafe</i></span></span>
			</div>
		</div>
	</footer>
	<script type="text/javascript" id="jquery-js" src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.0/jquery.min.js"></script>
	<script type="text/javascript" id="materialize-js" src="https://cdnjs.cloudflare.com/ajax/libs/materialize/0.100.2/js/materialize.min.js"></script>
	<script type="text/javascript" id="main-js" src="res/main.js"></script>
</body>
</html>