# ◈ JSCollector — Burp Suite Extension
> Passive, high-performance JavaScript surface mapper for bug bounty & red team engagements

---

## Overview

JSCollector silently monitors all HTTP traffic flowing through Burp Suite and extracts every JavaScript file URL it encounters. It deduplicates, normalizes, highlights sensitive files, and surfaces everything in a clean terminal-aesthetic tab.

**Zero active scanning. Zero external API calls. 100% passive.**

---

## Features

| Feature | Detail |
|---|---|
| Passive collection | Hooks IHttpListener + IProxyListener |
| Multi-source extraction | Proxy traffic, Sitemap, Scanner, Repeater, Intruder |
| Pattern coverage | `<script src>`, inline strings, absolute URLs, dynamic imports, source maps |
| Deduplication | ConcurrentHashMap keyed on normalized URL |
| Response dedup | SHA/hash cache prevents re-processing identical responses |
| Gzip/Deflate support | Transparent decompression before parsing |
| Relative → Absolute | Resolves relative paths against request base URL |
| Sensitive flagging | Highlights JS files containing: `api_key`, `token`, `secret`, `auth`, `bearer`, `graphql`, `webhook`, and more |
| Sitemap rescan | Seeds from existing Burp sitemap on startup + manual rescan button |
| Filter | Real-time domain/path filter in UI |
| Copy All | One-click copy of all collected URLs |
| Export | Save to timestamped `.txt` with source + sensitive tags |
| Clear | Full reset of URL map and response cache |
| Send to Repeater | Right-click selected JS URLs → Burp Repeater |
| Copy Selected | Right-click → copy selected rows |
| Thread-safe | All collections use concurrent structures; UI updates dispatched on EDT |

---

## Build Requirements

- **JDK 8+** (Java 8 minimum for Burp compatibility)
- **Burp Suite Pro or Community** (2.x API)
- `burp-extender-api.jar` (see below)

---

## Build Instructions

### Step 1 — Get the Burp Extender API JAR

**Option A — From Burp Suite directly (recommended):**
```
Burp Suite → Extender tab → APIs → Save interface files
```
Save as `lib/burp_extender_api.jar`

**Option B — Build from source:**
```bash
git clone https://github.com/PortSwigger/burp-extender-api
cd burp-extender-api
javac -d . burp/*.java
jar cf burp_extender_api.jar burp/
```

**Option C — Extract from Burp JAR:**
```bash
mkdir -p lib
unzip -j /path/to/burpsuite_pro_v*.jar 'burp/I*.class' 'burp/IBurpExtender*.class' -d lib/
```

### Step 2 — Compile and Package

```bash
chmod +x build.sh
./build.sh
```

Output: `JSCollector.jar`

### Step 3 — Load into Burp Suite

```
Burp Suite → Extender → Extensions → Add
  Extension type: Java
  Extension file: /path/to/JSCollector.jar
```

Check the **Output** tab — you should see:
```
[JS Collector] Extension loaded successfully.
[JS Collector] Passively monitoring all HTTP traffic for .js files...
[JS Collector] Seeding from N sitemap items...
```

---

## Usage

### Basic workflow (bug bounty)

1. Load the extension
2. Browse the target normally — JSCollector populates automatically
3. Open the **JS Collector** tab to review all discovered JS files
4. Use **Filter** to scope to a specific domain/subdomain
5. Flag **⚠ SENSITIVE** rows — these JS files contain API keys, tokens, secrets
6. Right-click → **Send to Repeater** to fetch and analyze each file
7. **Export** the full list for offline analysis with tools like:
   - `LinkFinder`
   - `SecretFinder`
   - `trufflehog`
   - `semgrep`

### Example export workflow

```bash
# Export from JSCollector → js_urls_1234567890.txt
# Then run SecretFinder against each:
while IFS= read -r url; do
    python3 SecretFinder.py -i "$url" -o cli
done < js_urls_1234567890.txt
```

---

## Detection Coverage

### Patterns matched

```
<script src="https://cdn.example.com/app.js">
<script src='/assets/bundle.js?v=3'>
<script src=app.min.js>                          # unquoted src

import('/js/vendor/react.js')                    # dynamic import string
fetch('/api/v2/client.js')                        # fetch call
require('../lib/utils.js')                        # CommonJS require string

https://cdn.jsdelivr.net/npm/axios.min.js         # absolute URL in body
//cdn.example.com/bootstrap.bundle.min.js         # protocol-relative

//# sourceMappingURL=main.chunk.js.map            # source map reference
```

### Sensitive keyword scan (first 8KB of each JS response)

```
api_key / apikey / API_KEY
access_token / accessToken
auth_token / authToken
client_secret
private_key
bearer
password / passwd
aws_key
stripe_key
firebase
endpoint
graphql
webhook
```

---

## Architecture

```
IBurpExtender.registerExtenderCallbacks()
  ├── registerHttpListener()     → IHttpListener.processHttpMessage()
  ├── registerProxyListener()    → IProxyListener.processProxyMessage()
  └── addSuiteTab()              → JSCollectorPanel (Swing UI)

processHttpMessage / processProxyMessage
  └── workerPool.submit(analyzeResponse)  ← non-blocking, 2-thread pool
        ├── decompress (gzip/deflate)
        ├── hash check (skip if seen)
        ├── extractJsUrls()
        │     ├── SCRIPT_SRC pattern
        │     ├── SCRIPT_SRC_UNQUOTED pattern
        │     ├── INLINE_JS_URL pattern
        │     ├── ABSOLUTE_JS_URL pattern
        │     └── SOURCE_MAP pattern
        ├── normalizeUrl() → relative → absolute
        └── storeUrl() → ConcurrentHashMap + EDT UI update
```

---

## Performance Notes

- **Worker pool**: 2 daemon threads — won't block Burp's proxy pipeline
- **Hash cache**: Avoids reprocessing identical responses (handles browser cache replays)
- **Compiled patterns**: All regex pre-compiled as static finals — zero recompilation overhead
- **Selective parsing**: Only parses HTML/JS/JSON content types (ignores images, binary, etc.)
- **Body size cap**: Decompressed bodies capped at 10MB — prevents OOM on huge bundles
- **Sensitive scan cap**: Only first 8KB scanned for keyword matching

---

## Troubleshooting

| Issue | Fix |
|---|---|
| No URLs appearing | Ensure Burp proxy is intercepting traffic; check Output tab for errors |
| Build fails | Verify JDK version `java -version` ≥ 1.8; confirm burp_extender_api.jar is in `lib/` |
| Missing some JS files | Some SPAs load JS via XHR/fetch — browse deeply or use Burp's active scan |
| UI not loading | Check Errors tab in Extender for Swing initialization exceptions |
| Duplicate base paths | By design: distinct query parameters are considered unique (e.g. `app.js?v=1` vs `app.js?v=2`) |

---

## Compatibility

- Burp Suite Community and Pro **2.x**
- Java 8, 11, 17, 21
- macOS, Linux, Windows

---

## Legal

For authorized penetration testing and bug bounty programs only.
