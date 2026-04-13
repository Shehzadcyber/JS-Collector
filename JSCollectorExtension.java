package burp;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.border.*;
import javax.swing.event.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.datatransfer.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.regex.*;
import java.util.zip.*;

/**
 * JSCollector - High-Performance Burp Suite Extension
 * Passively collects all JavaScript file URLs from Proxy traffic and Sitemap.
 *
 * Author: Generated for Bug Bounty / Penetration Testing
 * Burp API: 2.x compatible (IBurpExtender, IHttpListener, IProxyListener, ITab)
 */
public class JSCollectorExtension implements IBurpExtender, IHttpListener, IProxyListener, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    // ─── Thread-safe URL storage ───────────────────────────────────────────────
    // Key: normalized URL string → Value: JSEntry metadata
    private final ConcurrentHashMap<String, JSEntry> jsUrlMap = new ConcurrentHashMap<>(512);

    // Response hash cache to avoid re-processing identical responses
    private final Set<Integer> processedHashes = Collections.newSetFromMap(
            new ConcurrentHashMap<>(1024));

    // ─── Compiled Regex Patterns (performance: pre-compiled) ──────────────────
    // <script src="..."> or <script src='...'>
    private static final Pattern SCRIPT_SRC = Pattern.compile(
            "<script[^>]+src=[\"']([^\"']+\\.js(?:[?#][^\"']*)?)[\"']",
            Pattern.CASE_INSENSITIVE);

    // Bare .js URLs inside strings/code (catches dynamic imports, fetch calls, etc.)
    private static final Pattern INLINE_JS_URL = Pattern.compile(
            "[\"'`]([a-zA-Z0-9/._~:@!$&'()*+,;=%-]*\\.js(?:[?#][^\"'`\\s]*)?)[\"'`]");

    // Absolute URLs in any context
    private static final Pattern ABSOLUTE_JS_URL = Pattern.compile(
            "https?://[\\w./-]+\\.js(?:[?#][^\\s\"'<>]*)?",
            Pattern.CASE_INSENSITIVE);

    // src= attributes that don't use quotes (edge case in minified HTML)
    private static final Pattern SCRIPT_SRC_UNQUOTED = Pattern.compile(
            "<script[^>]+src=([^\\s>\"'][^\\s>]*\\.js[^\\s>]*)",
            Pattern.CASE_INSENSITIVE);

    // JS source map reference (//# sourceMappingURL=...)
    private static final Pattern SOURCE_MAP = Pattern.compile(
            "//[#@]\\s*sourceMappingURL=([^\\s]+\\.js(?:\\.map)?)",
            Pattern.CASE_INSENSITIVE);

    // Keywords that flag a JS file as interesting
    private static final Pattern SENSITIVE_KEYWORDS = Pattern.compile(
            "(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|" +
            "bearer|password|passwd|private[_-]?key|client[_-]?secret|" +
            "aws[_-]?key|stripe[_-]?key|firebase|endpoint|graphql|webhook)",
            Pattern.CASE_INSENSITIVE);

    // ─── UI Components ─────────────────────────────────────────────────────────
    private JSCollectorPanel uiPanel;

    // ─── Background worker pool ────────────────────────────────────────────────
    private final ExecutorService workerPool = Executors.newFixedThreadPool(
            2, r -> {
                Thread t = new Thread(r, "JSCollector-Worker");
                t.setDaemon(true);
                return t;
            });

    // ─── Stats ─────────────────────────────────────────────────────────────────
    private final AtomicInteger totalProcessed = new AtomicInteger(0);

    // ──────────────────────────────────────────────────────────────────────────
    // IBurpExtender
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks   = callbacks;
        this.helpers     = callbacks.getHelpers();
        this.stdout      = new PrintWriter(callbacks.getStdout(), true);
        this.stderr      = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName("JS Collector");

        // Register listeners
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);

        // Build and register UI tab on EDT
        SwingUtilities.invokeLater(() -> {
            uiPanel = new JSCollectorPanel();
            callbacks.addSuiteTab(JSCollectorExtension.this);
        });

        stdout.println("[JS Collector] Extension loaded successfully.");
        stdout.println("[JS Collector] Passively monitoring all HTTP traffic for .js files...");

        // Seed from existing sitemap on a background thread
        workerPool.submit(this::seedFromSitemap);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ITab
    // ──────────────────────────────────────────────────────────────────────────

    @Override public String getTabCaption()  { return "JS Collector"; }
    @Override public Component getUiComponent() { return uiPanel; }

    // ──────────────────────────────────────────────────────────────────────────
    // IHttpListener  (Scanner / Intruder / Repeater / Sequencer etc.)
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {
        if (messageIsRequest) return;
        // Process asynchronously to avoid blocking Burp's pipeline
        workerPool.submit(() -> analyzeResponse(messageInfo, resolveSource(toolFlag)));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // IProxyListener  (Proxy intercept — highest fidelity source)
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    public void processProxyMessage(boolean messageIsRequest,
                                    IInterceptedProxyMessage message) {
        if (messageIsRequest) return;
        workerPool.submit(() ->
                analyzeResponse(message.getMessageInfo(), "Proxy"));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Core Response Analysis
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Main analysis pipeline for a single HTTP response.
     * 1. Decompress body (gzip/deflate/identity)
     * 2. Hash check — skip if already processed
     * 3. Determine content type
     * 4. Extract JS URLs with all patterns
     * 5. Normalize and store
     */
    private void analyzeResponse(IHttpRequestResponse messageInfo, String source) {
        try {
            byte[] responseBytes = messageInfo.getResponse();
            if (responseBytes == null || responseBytes.length == 0) return;

            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            int bodyOffset = responseInfo.getBodyOffset();
            if (bodyOffset >= responseBytes.length) return;

            // Decompress body
            byte[] bodyBytes = decompress(responseBytes, bodyOffset,
                    responseBytes.length - bodyOffset, responseInfo.getHeaders());
            if (bodyBytes == null || bodyBytes.length == 0) return;

            // Dedup check via body hash (avoids re-processing cached responses)
            int bodyHash = Arrays.hashCode(bodyBytes);
            if (!processedHashes.add(bodyHash)) return;

            totalProcessed.incrementAndGet();

            String contentType = getContentType(responseInfo.getHeaders());
            String body = new String(bodyBytes, StandardCharsets.UTF_8);

            // Derive base URL for relative→absolute resolution
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            URL requestUrl = requestInfo.getUrl();
            String baseUrl = requestUrl.getProtocol() + "://" + requestUrl.getHost()
                    + (requestUrl.getPort() > 0 && requestUrl.getPort() != 80
                       && requestUrl.getPort() != 443 ? ":" + requestUrl.getPort() : "");

            // If this response itself IS a .js file — register it directly
            String reqPath = requestUrl.getPath();
            if (reqPath != null && reqPath.toLowerCase().endsWith(".js")) {
                String normalized = normalizeUrl(requestUrl.toString(), baseUrl);
                if (normalized != null) {
                    boolean sensitive = isSensitive(body);
                    storeUrl(normalized, source, sensitive);
                }
            }

            // Only parse for embedded URLs in HTML, JS, and JSON
            if (!isParseableContentType(contentType) && !reqPath.endsWith(".js")
                    && !reqPath.endsWith(".html") && !reqPath.endsWith(".htm")) return;

            Set<String> discovered = extractJsUrls(body);
            for (String raw : discovered) {
                String normalized = normalizeUrl(raw, baseUrl);
                if (normalized != null) {
                    // For relative paths we can't easily fetch content to check keywords
                    // Flag based on the URL path itself
                    boolean sensitive = SENSITIVE_KEYWORDS.matcher(normalized).find();
                    storeUrl(normalized, source, sensitive);
                }
            }

        } catch (Exception e) {
            // Silently swallow to avoid interfering with Burp's pipeline
            stderr.println("[JS Collector] Error processing response: " + e.getMessage());
        }
    }

    /**
     * Extract all candidate JS URLs from response body using all patterns.
     */
    private Set<String> extractJsUrls(String body) {
        Set<String> results = new LinkedHashSet<>(16);

        applyPattern(SCRIPT_SRC, body, 1, results);
        applyPattern(SCRIPT_SRC_UNQUOTED, body, 1, results);
        applyPattern(INLINE_JS_URL, body, 1, results);
        applyPattern(ABSOLUTE_JS_URL, body, 0, results);  // group 0 = whole match
        applyPattern(SOURCE_MAP, body, 1, results);

        return results;
    }

    private void applyPattern(Pattern p, String body, int group, Set<String> out) {
        Matcher m = p.matcher(body);
        while (m.find()) {
            try {
                String candidate = group == 0 ? m.group() : m.group(group);
                if (candidate != null && !candidate.isEmpty()) {
                    out.add(candidate.trim());
                }
            } catch (Exception ignored) {}
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // URL Normalization
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Normalize a raw URL candidate:
     * - Handle protocol-relative (//cdn.example.com/...)
     * - Handle absolute paths (/assets/app.js)
     * - Handle relative paths (../js/main.js)
     * - Validate final URL has .js extension
     * - Strip fragment
     */
    private String normalizeUrl(String raw, String baseUrl) {
        if (raw == null || raw.isEmpty()) return null;
        try {
            raw = raw.trim();

            // Strip fragment
            int fragIdx = raw.indexOf('#');
            if (fragIdx != -1) raw = raw.substring(0, fragIdx);

            String lower = raw.toLowerCase();

            // Must ultimately point to a .js resource (before any query string)
            String pathPart = raw.contains("?") ? raw.substring(0, raw.indexOf('?')) : raw;
            if (!pathPart.toLowerCase().endsWith(".js")) return null;

            // Skip data URIs and obvious non-HTTP schemes
            if (lower.startsWith("data:") || lower.startsWith("javascript:")
                    || lower.startsWith("vbscript:")) return null;

            String resolved;
            if (lower.startsWith("http://") || lower.startsWith("https://")) {
                resolved = raw;
            } else if (raw.startsWith("//")) {
                // Protocol-relative
                resolved = "https:" + raw;
            } else if (raw.startsWith("/")) {
                resolved = baseUrl + raw;
            } else {
                // Relative path — do a best-effort resolution
                resolved = baseUrl + "/" + raw;
            }

            // Validate with URL constructor
            new URL(resolved);
            return resolved;

        } catch (Exception e) {
            return null;
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Storage
    // ──────────────────────────────────────────────────────────────────────────

    private void storeUrl(String url, String source, boolean sensitive) {
        boolean isNew = jsUrlMap.putIfAbsent(url,
                new JSEntry(url, source, sensitive)) == null;
        if (isNew && uiPanel != null) {
            SwingUtilities.invokeLater(() -> uiPanel.addEntry(url, source, sensitive));
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Sitemap Seeding
    // ──────────────────────────────────────────────────────────────────────────

    /** Scan Burp's existing sitemap for .js responses on startup. */
    private void seedFromSitemap() {
        try {
            IHttpRequestResponse[] sitemapItems = callbacks.getSiteMap(null);
            if (sitemapItems == null) return;
            stdout.println("[JS Collector] Seeding from " + sitemapItems.length + " sitemap items...");
            for (IHttpRequestResponse item : sitemapItems) {
                analyzeResponse(item, "Sitemap");
            }
            stdout.println("[JS Collector] Sitemap seed complete. Found "
                    + jsUrlMap.size() + " unique JS URLs.");
        } catch (Exception e) {
            stderr.println("[JS Collector] Sitemap seed error: " + e.getMessage());
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private String resolveSource(int toolFlag) {
        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:    return "Proxy";
            case IBurpExtenderCallbacks.TOOL_SCANNER:  return "Scanner";
            case IBurpExtenderCallbacks.TOOL_INTRUDER: return "Intruder";
            case IBurpExtenderCallbacks.TOOL_REPEATER: return "Repeater";
            case IBurpExtenderCallbacks.TOOL_SPIDER:   return "Spider";
            case IBurpExtenderCallbacks.TOOL_TARGET:   return "Target";
            default:                                   return "Other";
        }
    }

    private String getContentType(List<String> headers) {
        for (String h : headers) {
            if (h.toLowerCase().startsWith("content-type:")) {
                return h.substring(13).toLowerCase().trim();
            }
        }
        return "";
    }

    private boolean isParseableContentType(String ct) {
        return ct.contains("html") || ct.contains("javascript")
                || ct.contains("json") || ct.contains("text/plain")
                || ct.contains("xml");
    }

    private boolean isSensitive(String body) {
        // Limit scan to first 8KB for performance on huge minified bundles
        String sample = body.length() > 8192 ? body.substring(0, 8192) : body;
        return SENSITIVE_KEYWORDS.matcher(sample).find();
    }

    /**
     * Decompress response body handling gzip, deflate, and identity encodings.
     */
    private byte[] decompress(byte[] response, int offset, int length,
                               List<String> headers) {
        String encoding = "";
        for (String h : headers) {
            if (h.toLowerCase().startsWith("content-encoding:")) {
                encoding = h.substring(17).trim().toLowerCase();
                break;
            }
        }

        byte[] raw = Arrays.copyOfRange(response, offset, offset + length);

        try {
            if (encoding.contains("gzip")) {
                return readStream(new GZIPInputStream(new ByteArrayInputStream(raw)));
            } else if (encoding.contains("deflate")) {
                return readStream(new InflaterInputStream(new ByteArrayInputStream(raw)));
            }
        } catch (IOException e) {
            // Fall through and return raw bytes (may be partially decompressed)
        }
        return raw;
    }

    private byte[] readStream(InputStream is) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(4096);
        byte[] tmp = new byte[4096];
        int n;
        // Safety cap: 10 MB decompressed limit
        int total = 0;
        while ((n = is.read(tmp)) != -1) {
            buf.write(tmp, 0, n);
            total += n;
            if (total > 10 * 1024 * 1024) break;
        }
        return buf.toByteArray();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Data Model
    // ──────────────────────────────────────────────────────────────────────────

    static class JSEntry {
        final String url;
        final String source;
        final boolean sensitive;
        final long timestamp;

        JSEntry(String url, String source, boolean sensitive) {
            this.url       = url;
            this.source    = source;
            this.sensitive = sensitive;
            this.timestamp = System.currentTimeMillis();
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // UI PANEL
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Main UI panel for the "JS Collector" Burp tab.
     * Dark terminal aesthetic — fits naturally inside Burp's dark theme.
     */
    class JSCollectorPanel extends JPanel {

        // Table model data — accessed only on EDT
        private final List<Object[]> tableData = new ArrayList<>(256);
        private JSTableModel tableModel;
        private JTable table;
        private JTextField filterField;
        private JLabel statusLabel;
        private JLabel countLabel;

        // ─── Color Palette ─────────────────────────────────────────────────
        // Java 8: static non-primitive fields not allowed in non-static inner classes,
        // so declare as instance finals (initialized once, effectively constant)
        private final Color BG_DARK    = new Color(18, 20, 26);
        private final Color BG_PANEL   = new Color(24, 27, 35);
        private final Color BG_ROW_ALT = new Color(28, 32, 42);
        private final Color ACCENT     = new Color(80, 220, 140);    // terminal green
        private final Color ACCENT2    = new Color(60, 180, 255);    // cyan
        private final Color WARN       = new Color(255, 180, 50);    // amber warning
        private final Color TEXT_MAIN  = new Color(210, 220, 235);
        private final Color TEXT_DIM   = new Color(110, 125, 145);
        private final Color BORDER_COL = new Color(40, 48, 62);
        private final Color BTN_BG     = new Color(35, 42, 58);
        private final Color BTN_HOVER  = new Color(50, 60, 82);

        JSCollectorPanel() {
            setLayout(new BorderLayout(0, 0));
            setBackground(BG_DARK);
            setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
            buildUI();
        }

        private void buildUI() {
            add(buildHeaderBar(),  BorderLayout.NORTH);
            add(buildTableArea(),  BorderLayout.CENTER);
            add(buildStatusBar(),  BorderLayout.SOUTH);
        }

        // ── Header ────────────────────────────────────────────────────────────
        private JPanel buildHeaderBar() {
            JPanel header = new JPanel(new BorderLayout(12, 0));
            header.setBackground(BG_PANEL);
            header.setBorder(new CompoundBorder(
                    new MatteBorder(0, 0, 1, 0, BORDER_COL),
                    new EmptyBorder(10, 14, 10, 14)));

            // Left: logo + title
            JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            left.setOpaque(false);

            JLabel logo = new JLabel("◈ JS COLLECTOR");
            logo.setFont(new Font("Monospaced", Font.BOLD, 15));
            logo.setForeground(ACCENT);
            left.add(logo);

            JLabel sub = new JLabel("passive javascript surface mapper");
            sub.setFont(new Font("Monospaced", Font.PLAIN, 10));
            sub.setForeground(TEXT_DIM);
            left.add(sub);

            // Right: filter + action buttons
            JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
            right.setOpaque(false);

            JLabel filterLabel = new JLabel("filter:");
            filterLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
            filterLabel.setForeground(TEXT_DIM);
            right.add(filterLabel);

            filterField = new JTextField(18);
            filterField.setBackground(new Color(30, 36, 50));
            filterField.setForeground(TEXT_MAIN);
            filterField.setCaretColor(ACCENT);
            filterField.setFont(new Font("Monospaced", Font.PLAIN, 11));
            filterField.setBorder(new CompoundBorder(
                    new LineBorder(BORDER_COL, 1),
                    new EmptyBorder(3, 6, 3, 6)));
            filterField.getDocument().addDocumentListener(new DocumentListener() {
                public void insertUpdate(DocumentEvent e)  { applyFilter(); }
                public void removeUpdate(DocumentEvent e)  { applyFilter(); }
                public void changedUpdate(DocumentEvent e) { applyFilter(); }
            });
            right.add(filterField);

            right.add(makeButton("Copy All",       ACCENT,  e -> copyAll()));
            right.add(makeButton("Export",         ACCENT2, e -> exportToFile()));
            right.add(makeButton("Sitemap Rescan", ACCENT2, e -> workerPool.submit(JSCollectorExtension.this::seedFromSitemap)));
            right.add(makeButton("Clear",          new Color(220, 80, 80), e -> clearAll()));

            header.add(left,  BorderLayout.WEST);
            header.add(right, BorderLayout.EAST);
            return header;
        }

        // ── Table ─────────────────────────────────────────────────────────────
        private JScrollPane buildTableArea() {
            tableModel = new JSTableModel();
            table = new JTable(tableModel);

            // ── Appearance ──
            table.setBackground(BG_DARK);
            table.setForeground(TEXT_MAIN);
            table.setGridColor(BORDER_COL);
            table.setSelectionBackground(new Color(45, 65, 95));
            table.setSelectionForeground(Color.WHITE);
            table.setFont(new Font("Monospaced", Font.PLAIN, 12));
            table.setRowHeight(22);
            table.setShowHorizontalLines(true);
            table.setShowVerticalLines(false);
            table.setIntercellSpacing(new Dimension(0, 1));
            table.setFillsViewportHeight(true);
            table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

            // ── Header ──
            JTableHeader th = table.getTableHeader();
            th.setBackground(new Color(28, 34, 48));
            th.setForeground(ACCENT2);
            th.setFont(new Font("Monospaced", Font.BOLD, 11));
            th.setBorder(new MatteBorder(0, 0, 1, 0, BORDER_COL));

            // ── Column widths ──
            table.getColumnModel().getColumn(0).setPreferredWidth(540); // URL
            table.getColumnModel().getColumn(1).setPreferredWidth(80);  // Source
            table.getColumnModel().getColumn(2).setPreferredWidth(65);  // Sensitive

            // ── Custom cell renderer for sensitive highlighting ──
            table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable table,
                        Object value, boolean isSelected, boolean hasFocus,
                        int row, int col) {
                    super.getTableCellRendererComponent(table, value,
                            isSelected, hasFocus, row, col);

                    boolean sensitive = Boolean.TRUE.equals(
                            tableModel.getValueAt(row, 2));

                    if (!isSelected) {
                        if (sensitive) {
                            setBackground(new Color(55, 40, 20));
                            setForeground(WARN);
                        } else {
                            setBackground(row % 2 == 0 ? BG_DARK : BG_ROW_ALT);
                            setForeground(col == 1 ? ACCENT2 : TEXT_MAIN);
                        }
                    }
                    setFont(new Font("Monospaced", Font.PLAIN, 12));
                    setBorder(new EmptyBorder(0, 8, 0, 4));
                    return this;
                }
            });

            // ── Right-click context menu ──
            JPopupMenu popup = buildContextMenu();
            table.setComponentPopupMenu(popup);
            table.addMouseListener(new MouseAdapter() {
                @Override public void mousePressed(MouseEvent e) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0 && !table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                }
            });

            // ── Sorting ──
            table.setAutoCreateRowSorter(true);

            JScrollPane scroll = new JScrollPane(table);
            scroll.setBackground(BG_DARK);
            scroll.getViewport().setBackground(BG_DARK);
            scroll.setBorder(BorderFactory.createEmptyBorder());
            scroll.getVerticalScrollBar().setBackground(BG_PANEL);
            return scroll;
        }

        // ── Status Bar ────────────────────────────────────────────────────────
        private JPanel buildStatusBar() {
            JPanel bar = new JPanel(new BorderLayout());
            bar.setBackground(new Color(14, 16, 22));
            bar.setBorder(new CompoundBorder(
                    new MatteBorder(1, 0, 0, 0, BORDER_COL),
                    new EmptyBorder(4, 14, 4, 14)));

            statusLabel = new JLabel("● LISTENING — monitoring all proxy traffic");
            statusLabel.setFont(new Font("Monospaced", Font.PLAIN, 10));
            statusLabel.setForeground(ACCENT);

            countLabel = new JLabel("0 unique JS URLs");
            countLabel.setFont(new Font("Monospaced", Font.PLAIN, 10));
            countLabel.setForeground(TEXT_DIM);

            bar.add(statusLabel, BorderLayout.WEST);
            bar.add(countLabel,  BorderLayout.EAST);
            return bar;
        }

        // ── Context Menu ──────────────────────────────────────────────────────
        private JPopupMenu buildContextMenu() {
            JPopupMenu menu = new JPopupMenu();
            menu.setBackground(BTN_BG);
            menu.setBorder(new LineBorder(BORDER_COL, 1));

            JMenuItem copySelected = styledMenuItem("Copy Selected URLs");
            copySelected.addActionListener(e -> copySelected());
            menu.add(copySelected);

            JMenuItem sendRepeater = styledMenuItem("Send to Repeater");
            sendRepeater.addActionListener(e -> sendToRepeater());
            menu.add(sendRepeater);

            menu.addSeparator();

            JMenuItem copyAll = styledMenuItem("Copy All URLs");
            copyAll.addActionListener(e -> copyAll());
            menu.add(copyAll);

            return menu;
        }

        private JMenuItem styledMenuItem(String text) {
            JMenuItem item = new JMenuItem(text);
            item.setBackground(BTN_BG);
            item.setForeground(TEXT_MAIN);
            item.setFont(new Font("Monospaced", Font.PLAIN, 11));
            item.setBorder(new EmptyBorder(4, 10, 4, 10));
            return item;
        }

        // ── Button Factory ────────────────────────────────────────────────────
        private JButton makeButton(String text, Color accent, ActionListener al) {
            JButton btn = new JButton(text);
            btn.setFont(new Font("Monospaced", Font.BOLD, 10));
            btn.setForeground(accent);
            btn.setBackground(BTN_BG);
            btn.setBorder(new CompoundBorder(
                    new LineBorder(new Color(accent.getRed(), accent.getGreen(),
                            accent.getBlue(), 80), 1),
                    new EmptyBorder(4, 10, 4, 10)));
            btn.setFocusPainted(false);
            btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            btn.addMouseListener(new MouseAdapter() {
                public void mouseEntered(MouseEvent e) { btn.setBackground(BTN_HOVER); }
                public void mouseExited(MouseEvent e)  { btn.setBackground(BTN_BG); }
            });
            btn.addActionListener(al);
            return btn;
        }

        // ── Public API (called from worker thread, must dispatch to EDT) ───────
        void addEntry(String url, String source, boolean sensitive) {
            // Called on EDT via SwingUtilities.invokeLater in storeUrl()
            String flag = sensitive ? "⚠ YES" : "—";
            tableData.add(new Object[]{url, source, sensitive, flag});
            tableModel.fireTableRowsInserted(tableData.size() - 1, tableData.size() - 1);
            updateCount();
        }

        // ── Actions ───────────────────────────────────────────────────────────
        private void applyFilter() {
            String term = filterField.getText().trim().toLowerCase();
            tableModel.setFilter(term);
        }

        private void copyAll() {
            StringBuilder sb = new StringBuilder();
            for (Object[] row : tableData) {
                sb.append(row[0]).append('\n');
            }
            setClipboard(sb.toString());
            flash("✓ Copied " + tableData.size() + " URLs");
        }

        private void copySelected() {
            int[] selected = table.getSelectedRows();
            if (selected.length == 0) return;
            StringBuilder sb = new StringBuilder();
            for (int r : selected) {
                int modelRow = table.convertRowIndexToModel(r);
                sb.append(tableModel.getRow(modelRow)[0]).append('\n');
            }
            setClipboard(sb.toString());
            flash("✓ Copied " + selected.length + " URLs");
        }

        private void sendToRepeater() {
            int[] selected = table.getSelectedRows();
            if (selected.length == 0) return;
            int sent = 0;
            for (int r : selected) {
                try {
                    int modelRow = table.convertRowIndexToModel(r);
                    String url = (String) tableModel.getRow(modelRow)[0];
                    URL parsed = new URL(url);
                    boolean https = parsed.getProtocol().equalsIgnoreCase("https");
                    int port = parsed.getPort() != -1 ? parsed.getPort()
                                                      : (https ? 443 : 80);
                    String path = parsed.getPath().isEmpty() ? "/" : parsed.getPath();
                    if (parsed.getQuery() != null) path += "?" + parsed.getQuery();

                    String req = "GET " + path + " HTTP/1.1\r\n"
                               + "Host: " + parsed.getHost() + "\r\n"
                               + "User-Agent: Mozilla/5.0\r\n"
                               + "Accept: */*\r\n\r\n";

                    callbacks.sendToRepeater(parsed.getHost(), port, https,
                            req.getBytes(StandardCharsets.UTF_8), "JS: " + parsed.getHost());
                    sent++;
                } catch (Exception ex) {
                    stderr.println("[JS Collector] Repeater error: " + ex.getMessage());
                }
            }
            flash("✓ Sent " + sent + " URLs to Repeater");
        }

        private void exportToFile() {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Export JS URLs");
            fc.setSelectedFile(new File("js_urls_" + System.currentTimeMillis() + ".txt"));
            int result = fc.showSaveDialog(this);
            if (result != JFileChooser.APPROVE_OPTION) return;
            try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
                for (Object[] row : tableData) {
                    pw.println(row[0] + "\t[" + row[1] + "]"
                            + (Boolean.TRUE.equals(row[2]) ? "\t[SENSITIVE]" : ""));
                }
                flash("✓ Exported " + tableData.size() + " URLs → " + fc.getSelectedFile().getName());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this,
                        "Export failed: " + e.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }

        private void clearAll() {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Clear all collected JS URLs?", "Confirm Clear",
                    JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                jsUrlMap.clear();
                processedHashes.clear();
                tableData.clear();
                tableModel.fireTableDataChanged();
                updateCount();
                flash("Cleared");
            }
        }

        private void setClipboard(String text) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
        }

        private void updateCount() {
            int total    = tableData.size();
            long sensitive = tableData.stream()
                    .filter(r -> Boolean.TRUE.equals(r[2])).count();
            countLabel.setText(total + " unique JS URLs"
                    + (sensitive > 0 ? "  ⚠ " + sensitive + " sensitive" : ""));
            countLabel.setForeground(sensitive > 0 ? WARN : TEXT_DIM);
        }

        private void flash(String msg) {
            String original = statusLabel.getText();
            statusLabel.setText("● " + msg);
            statusLabel.setForeground(ACCENT);
            javax.swing.Timer t = new javax.swing.Timer(2500, ev -> {
                statusLabel.setText("● LISTENING — monitoring all proxy traffic");
                statusLabel.setForeground(ACCENT);
            });
            t.setRepeats(false);
            t.start();
        }

        // ══════════════════════════════════════════════════════════════════════
        // Table Model with filter support
        // ══════════════════════════════════════════════════════════════════════
        class JSTableModel extends AbstractTableModel {

            private final String[] COLUMNS = {"JavaScript URL", "Source", "Sensitive"};
            private String filterTerm = "";

            @Override public int getRowCount()    { return getFiltered().size(); }
            @Override public int getColumnCount() { return 3; }
            @Override public String getColumnName(int col) { return COLUMNS[col]; }

            @Override
            public Object getValueAt(int row, int col) {
                List<Object[]> filtered = getFiltered();
                if (row >= filtered.size()) return "";
                Object[] entry = filtered.get(row);
                switch (col) {
                    case 0: return entry[0];  // URL
                    case 1: return entry[1];  // Source
                    case 2: return entry[3];  // Flag string "⚠ YES" or "—"
                    default: return "";
                }
            }

            /** Get raw row by model index (for actions) */
            Object[] getRow(int row) {
                List<Object[]> filtered = getFiltered();
                return row < filtered.size() ? filtered.get(row) : new Object[0];
            }

            void setFilter(String term) {
                this.filterTerm = term;
                fireTableDataChanged();
            }

            private List<Object[]> getFiltered() {
                if (filterTerm.isEmpty()) return tableData;
                List<Object[]> result = new ArrayList<>();
                for (Object[] row : tableData) {
                    String url    = ((String) row[0]).toLowerCase();
                    String source = ((String) row[1]).toLowerCase();
                    if (url.contains(filterTerm) || source.contains(filterTerm)) {
                        result.add(row);
                    }
                }
                return result;
            }
        }
    }
}
