<?php
// Flush GoDaddy's platform caches for this site. Run on the host as:
//     wp eval-file platform-cache-ban.php
// The system plugin sends its PURGE and BAN requests non-blocking, and a
// WP-CLI process exits before they finish, so this sends the same requests
// itself, to the public hostname, and waits for each answer; the gateway in
// front of the site accepts them from the host and drops both its own copy
// and the copy behind it. (The plugin also addresses an internal cache by
// IP; that address does not answer from the SSH host, so it is not tried.)
// Then the plugin's own ban runs from the shutdown hook for the CDN
// invalidation it also performs.
$paths = array('/', '/report', '/elyon-sol', '/index.html', '/report.html', '/elyon-sol.html');

function gsr_request($method, $url, $resolve, $host) {
    $ch = curl_init($url);
    curl_setopt_array($ch, array(
        CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_NOBODY => true,
        CURLOPT_TIMEOUT => 8, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_HTTPHEADER => array('Host: ' . $host),
    ));
    if ($resolve) { curl_setopt($ch, CURLOPT_RESOLVE, $resolve); }
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE); $err = curl_error($ch);
    curl_close($ch);
    return $code ? (string) $code : ('error: ' . $err);
}

$home = home_url(); $host = parse_url($home, PHP_URL_HOST);
$targets = array(array('public gateway', null));
foreach ($targets as $t) {
    list($label, $resolve) = $t;
    $codes = array();
    foreach (array('http', 'https') as $scheme) {
        $codes[] = $scheme . ' BAN ' . gsr_request('BAN', $scheme . '://' . $host . '/', $resolve, $host);
        foreach ($paths as $p) { $codes[] = $scheme . ' PURGE ' . $p . ' ' . gsr_request('PURGE', $scheme . '://' . $host . $p, $resolve, $host); }
    }
    fwrite(STDERR, $label . ": " . implode(', ', $codes) . "\n");
}
add_action('shutdown', function () {
    $c = isset($GLOBALS['wpaas_cache_class']) ? $GLOBALS['wpaas_cache_class'] : null;
    if (!$c) { fwrite(STDERR, "no platform cache class; CDN not flushed\n"); return; }
    $r = $c->ban();
    fwrite(STDERR, "platform plugin ban (CDN invalidation): " . ($r ? "sent" : "refused (throttled or disabled)") . "\n");
    sleep(2);     // let the plugin's own non-blocking requests leave before the process ends
}, 1);
