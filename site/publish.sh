#!/bin/sh
# Publish the three pages to elyon-sol.io (GoDaddy managed WordPress) and
# flush the platform page cache. Usage: ./publish.sh USER@HOST
# The SFTP user and password come from GoDaddy > Managed WordPress >
# Settings > SFTP/SSH; both change on every rotation. Cloudflare's cache
# must still be purged by hand afterwards (Caching > Configuration >
# Purge Everything).
set -eu
H="${1:?usage: publish.sh USER@HOST}"
D="$(cd "$(dirname "$0")" && pwd)"
scp -O "$D/index.html" "$D/report.html" "$D/elyon-sol.html" "$H:/html/"
scp -O "$D/zz-gargoyle-static-root.php" "$H:/html/wp-content/mu-plugins/"
scp -O "$D/platform-cache-ban.php" "$H:/tmp/platform-cache-ban.php"
ssh "$H" 'cd /html && sha256sum index.html report.html elyon-sol.html && wp eval-file /tmp/platform-cache-ban.php 2>&1 | grep -v Deprecated; rm -f /tmp/platform-cache-ban.php'
echo "now purge the Cloudflare cache, then check https://elyon-sol.io/"
