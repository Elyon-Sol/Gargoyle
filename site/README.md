# elyon-sol.io

Three self-contained pages, each with the stylesheet inlined, hosted on
GoDaddy (160.153.0.167) behind Cloudflare:

- index.html      Gargoyle front page: who it is for, what it proves, how it
                  works, evidence, get it, one status box
- report.html     the technical report (sections 1-12, references, appendices)
- elyon-sol.html  the predecessor's page as published, with a superseded
                  banner and the retirement timeline

The host is GoDaddy managed WordPress: nginx, no .htaccess, a root-owned
index.php that answers the site root, and a gateway page cache in front of
everything with a 31-day lifetime. The platform's cache ban refreshes
responses that went through PHP but not static files, so the pages are
served through a must-use plugin, wp-content/mu-plugins/zz-gargoyle-static-root.php
(copy in this folder), which maps GET or HEAD of these paths to the files:

    /            index.html
    /report      report.html
    /elyon-sol   elyon-sol.html

and leaves every other path to WordPress. Links between the pages use
those routes, never the .html names: the gateway cached the .html URLs on
first upload and will not let go of them. Delete the plugin file to give
the root back to WordPress.

Publishing, from a machine with the SFTP credentials (GoDaddy: Managed
WordPress > Settings > SFTP/SSH; user and password change on each rotation):

    ./publish.sh USER@898413.us33.ssh.myftpupload.com

which uploads the three pages and the plugin, prints their hashes on the
host, and runs platform-cache-ban.php through wp-cli. That last step
matters: GoDaddy keeps a page cache in front of the origin with a 31-day
lifetime, and `wp cache flush` does not touch it. The "cloudflare" server
header on responses is GoDaddy's gateway, not a Cloudflare zone of ours;
there is nothing to purge elsewhere. Check that https://elyon-sol.io/,
/report and /elyon-sol match the files, for instance with
`curl -s https://elyon-sol.io/report | sha256sum` against the local file.
First publish: 2026-10-20.

Open slot: a screenshot of the approval console with a held write's diff
card, taken from the enrolled approver's browser. Place it as
site/console.png (PNG, about 1200 px wide, accounts replaced or cropped
out) and add the figure to the "How it works" section of index.html.

Rules: ASCII only; no real account names, tenant ids or app ids (write
"<workstation account>", "<approver>"); every hash or number quoted from a
live run comes from the roadmap notes or a log, never from memory.
