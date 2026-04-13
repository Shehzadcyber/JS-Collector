
# JS-Collector

JS-Collector is a Burp Suite extension that automatically finds and collects all JavaScript (JS) URLs across Burp’s entire workspace—covering Burp HTTP history and tools such as JS Link Finder, JS Miner, and GAP. It consolidates results by removing duplicates, so you get a clean, unique list of JS endpoints to analyze.


## Installation Process (Clone + Install the `.jar` in Burp)

1. **Clone the repository**
   ```bash
   git clone https://github.com/Shehzadcyber/JS-Collector.git
   cd JS-Collector
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

