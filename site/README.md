# elyon-sol.io

Three self-contained pages, each with the stylesheet inlined, hosted on
GoDaddy (160.153.0.167) behind Cloudflare:

- index.html      Gargoyle front page: who it is for, what it proves, how it
                  works, evidence, get it, one status box
- report.html     the technical report (sections 1-12, references, appendices)
- elyon-sol.html  the predecessor's page as published, with a superseded
                  banner and the retirement timeline

The host is GoDaddy managed WordPress: nginx, no .htaccess, a root-owned
index.php that answers the site root. Static files in /html are served as
themselves, so the pages are plain uploads; the root is handed to
index.html by a must-use plugin, wp-content/mu-plugins/zz-gargoyle-static-root.php
(copy in this folder as zz-gargoyle-static-root.php), which serves
/html/index.html for GET or HEAD of "/" or "/index.php" and nothing else.
Delete that file to give the root back to WordPress.

Publishing, from a machine with the SFTP credentials (GoDaddy: Managed
WordPress > Settings > SFTP/SSH):

    scp -O index.html report.html elyon-sol.html USER@HOST:/html/
    ssh USER@HOST 'cd /html && wp cache flush'

then purge the Cloudflare cache for the zone (Caching > Configuration >
Purge Everything) and check https://elyon-sol.io/ shows the title
"Gargoyle - receipts and holds for agent tool calls". The plugin sends
Cache-Control max-age=600 on the root, but the platform overrides it with
a 31-day value, so the purge is not optional. First publish: 2026-10-20.

Open slot: a screenshot of the approval console with a held write's diff
card, taken from the enrolled approver's browser. Place it as
site/console.png (PNG, about 1200 px wide, accounts replaced or cropped
out) and add the figure to the "How it works" section of index.html.

Rules: ASCII only; no real account names, tenant ids or app ids (write
"<workstation account>", "<approver>"); every hash or number quoted from a
live run comes from the roadmap notes or a log, never from memory.
