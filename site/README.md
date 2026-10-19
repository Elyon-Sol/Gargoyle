# elyon-sol.io

Static site for Gargoyle, hosted on GoDaddy (160.153.0.167) behind Cloudflare.
Not GitHub Pages: changes here are not deployed until the files are uploaded.

Files:

- index.html        front page: what Gargoyle proves, how it works, how to get it
- dissertation.html the long-form account (model, spec, identity, evidence,
                    implementation, live evaluation, limits, field, references)
- elyon-sol.html    the predecessor's page, kept as published with a banner
                    saying it is superseded (Elyon-Sol retired 2026-07-20)
- style.css         one stylesheet for all three pages

Publishing:

1. Upload the four files to the web root (public_html) of the GoDaddy host,
   replacing index.html. cPanel File Manager or SFTP both work.
2. In Cloudflare, purge the cache for the zone (Caching > Configuration >
   Purge Everything), or the old page keeps being served.
3. Check https://elyon-sol.io/, /dissertation.html and /elyon-sol.html.

Rules for these files: ASCII only; no real account names, tenant ids or app
ids (write "<workstation account>", "<approver>"); every hash or number quoted
from a live run must come from the roadmap notes or a log, never from memory.
