# ZX305 Domain Mapper Report UI

This repository contains the pure HTML/CSS/JS dashboard downloaded by `PERES25A.s11.ZX305.sh`.

The Bash script fetches these files from:

```text
https://raw.githubusercontent.com/sagigolan8/zx305_report/main
```

## Files

- `index.html` - Report layout and JSON injection placeholders.
- `style.css` - Dark cybersecurity-themed styling.
- `script.js` - Data parsing, statistics, filtering, sorting, CVE links, and table rendering.

## JSON Injection Points

The Bash script injects scan data into:

```html
<script id="domainMapperData" type="application/json">[]</script>
<script id="domainMapperSummary" type="application/json">{}</script>
```

For compatibility with the earlier ZX301 dashboard, `script.js` also accepts `vulnerData`.

## Dashboard Features

- Statistics cards for hosts, open ports, high severity findings, CVEs, credentials, and AS-REP hashes.
- Sortable findings table.
- Filters for host, service, protocol, severity, and finding type.
- Credential badges when brute-force or spray results are present.
- CVE remediation links to the National Vulnerability Database.
- No external libraries or network dependencies after the files are downloaded.

## Local Test

Open `index.html` directly in a browser. Without injected data it will show an empty state. To test with real data, run the ZX305 Bash script and open the generated `index.html` from its output directory.
