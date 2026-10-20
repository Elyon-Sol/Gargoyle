# elyon-sol.io

Three self-contained pages, each with the stylesheet inlined, hosted on
GoDaddy (160.153.0.167) behind Cloudflare:

- index.html      Gargoyle front page: who it is for, what it proves, how it
                  works, evidence, get it, one status box
- report.html     the technical report (sections 1-12, references, appendices)
- elyon-sol.html  the predecessor's page as published, with a superseded
                  banner and the retirement timeline

The host runs WordPress in public_html, and WordPress answers the site root
through index.php. Static files in public_html are served as themselves
(https://elyon-sol.io/index.html already is), so the pages work once the
root prefers index.html:

1. Upload the three files to public_html, replacing any older index.html.
2. Add this line at the top of public_html/.htaccess, above the
   "# BEGIN WordPress" block:

       DirectoryIndex index.html index.php

   WordPress stays reachable at its own paths (/elyon-sol/, /wp-admin/).
3. If the Gargoyle HTML was pasted into the WordPress site editor's home
   template, remove that block there; it is not needed and WordPress
   rewrites its punctuation.
4. Purge the Cloudflare cache for the zone (Caching > Configuration >
   Purge Everything), then check https://elyon-sol.io/ shows the title
   "Gargoyle - receipts and holds for agent tool calls".

Open slot: a screenshot of the approval console with a held write's diff
card, taken from the enrolled approver's browser. Place it as
site/console.png (PNG, about 1200 px wide, accounts replaced or cropped
out) and add the figure to the "How it works" section of index.html.

Rules: ASCII only; no real account names, tenant ids or app ids (write
"<workstation account>", "<approver>"); every hash or number quoted from a
live run comes from the roadmap notes or a log, never from memory.
