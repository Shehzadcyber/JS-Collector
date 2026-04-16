# JS-Collector — Burp Suite Extension
> Passive, high-performance JavaScript surface mapper for bug bounty & red team engagements

---

## Overview

JS-Collector silently monitors all HTTP traffic flowing through Burp Suite and extracts every JavaScript file URL it encounters. It deduplicates, normalizes, highlights sensitive files, and surfaces everything in a clean terminal-aesthetic tab.

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

<img width="1918" height="1021" alt="image" src="https://github.com/user-attachments/assets/5b139f6d-9d26-4659-8504-a0f7ba6ee143" />



## Installation Process (Clone + Install the `.jar` in Burp)

1. **Clone the repository**
   ```bash
   git clone https://github.com/Shehzadcyber/JS-Collector.git
   Or download zip file for windows 
   ```

2. **Find the built `.jar` file**
   - Open the cloned folder and locate the `.jar` you want to install (for example in a `dist/`, `build/`, or `target/` directory).

3. **Copy the `.jar`**
   - Copy the `.jar` file somewhere easy to access (or leave it in the project folder).

4. **Open Burp Suite**
   - Launch Burp Suite normally.

5. **Load the extension**
   - Go to **Extender** tab → **Extensions** sub-tab.
   - Click **Add** (or **Import / Load** depending on your Burp version).
   - Select the `.jar` file you cloned/built.
   - Click **Next/OK** to load it.

6. **Enable / verify it loaded**
   - After loading, confirm it appears in the **Extensions** list and is enabled.
   - (Optional) Check the **Extender** → **Output** tab for any load errors or status logs.


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


## Compatibility

- Burp Suite Community and Pro **2.x**
- Java 8, 11, 17, 21
- macOS, Linux, Windows

---

