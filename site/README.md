# elyon-sol.io

One file, index.html, hosted on GoDaddy (160.153.0.167) behind Cloudflare.
The host currently serves only index.html, so the stylesheet, the
dissertation and the archived Elyon-Sol page are all inside it:

- #top .. #get      Gargoyle front page
- #diss, #sec-1 ..  the dissertation (sections 1-12, references, appendices)
- #archive, #es-*   the predecessor's page as published, with a superseded banner

Publishing: upload index.html to public_html, replacing the old one, then
purge the Cloudflare cache for the zone (Caching > Configuration > Purge
Everything) and check https://elyon-sol.io/.

Rules: ASCII only; no real account names, tenant ids or app ids (write
"<workstation account>", "<approver>"); every hash or number quoted from a
live run comes from the roadmap notes or a log, never from memory.
