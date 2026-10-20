<?php
// Flush GoDaddy's platform page cache for this site. The system plugin only
// honours ban() and purge() from the shutdown action, so hook there.
// Run on the host as: wp eval-file platform-cache-ban.php
add_action('shutdown', function () {
    $c = isset($GLOBALS['wpaas_cache_class']) ? $GLOBALS['wpaas_cache_class'] : null;
    if (!$c) { fwrite(STDERR, "no platform cache class; nothing flushed\n"); return; }
    $r = $c->ban();
    fwrite(STDERR, "platform cache ban: " . ($r ? "sent" : "refused (throttled or disabled)") . "\n");
    foreach (array('/', '/index.html', '/report.html', '/elyon-sol.html') as $p) {
        $c->purge(array(home_url($p)));
    }
    fwrite(STDERR, "purge sent for the root and the three pages\n");
}, 1);
