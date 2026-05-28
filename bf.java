import javafx.animation.*;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.*;
import javafx.geometry.*;
import javafx.scene.*;
import javafx.scene.chart.*;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;
import javafx.scene.paint.*;
import javafx.scene.shape.*;
import javafx.scene.text.*;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.text.SimpleDateFormat;
import java.util.*;

/**
 * BruteForceDetector — Brute Force Cyber Attack Detection Simulator
 *
 * <p>A JavaFX desktop application that monitors failed login attempts per IP address
 * and detects brute force attacks in real time using a <b>sliding window algorithm</b>
 * backed by two core data structures:</p>
 *
 * <ul>
 *   <li>{@code HashMap<String, LinkedList<Long>>} — maps each IP address to its
 *       ordered timestamp history (SEN2212: hash-based structures, O(1) avg lookup)</li>
 *   <li>{@code LinkedList<Long>} as a FIFO queue — stores Unix timestamps of recent
 *       failed attempts per IP (SEN2211: linked lists and queues, O(1) head/tail ops)</li>
 *   <li>{@code HashSet<String>} — tracks blocked IPs for O(1) membership testing</li>
 * </ul>
 *
 * <p><b>Algorithm overview (per incoming attempt):</b></p>
 * <ol>
 *   <li>Insert IP into HashMap if absent — O(1) average</li>
 *   <li>Append current timestamp to the LinkedList tail — O(1)</li>
 *   <li>Remove expired timestamps from the LinkedList head — amortised O(1)</li>
 *   <li>Compare list size against THRESHOLD — O(1)</li>
 * </ol>
 *
 * <p><b>Overall complexity:</b> O(1) amortised per attempt, O(I × T) space,
 * where I = unique IPs and T = threshold (default 5).</p>
 *
 * <p><b>Project:</b> SEN2211 / SEN2212 Data Structures</p>
 * <p><b>Authors:</b> Glory Mturi Elias, Cem Suay Asıldoğan, Deniz Doga</p>
 */
public class BruteForceDetector extends Application {

    // ── Core detection state (original logic) ──────────────────────────────────

    /**
     * Primary data structure — maps each IP address string to its attempt history.
     *
     * <p>Chosen over TreeMap (O(log n) lookup) and array/list (O(n) lookup) because
     * HashMap provides O(1) average-case get() and putIfAbsent() operations via
     * Java's separate-chaining with tree-ification (Java 8+).</p>
     *
     * <p>Key: IP address string (e.g. "192.168.1.50")</p>
     * <p>Value: LinkedList of Unix timestamps (ms) for recent failed attempts</p>
     */
    private final HashMap<String, LinkedList<Long>> loginAttempts = new HashMap<>();

    /**
     * Maximum number of failed login attempts allowed within the TIME_WINDOW
     * before an IP is flagged as an attacker.
     * Default: 5. Configurable at runtime via the threshold spinner.
     */
    private int THRESHOLD = 5;

    /**
     * The sliding window duration in milliseconds. Only timestamps within the last
     * TIME_WINDOW ms are considered when evaluating whether an IP exceeds THRESHOLD.
     * Default: 10,000 ms (10 seconds). Configurable at runtime via the window spinner.
     */
    private long TIME_WINDOW = 10_000;

    /** Running total of all logged attempts across all IPs since the last reset. */
    private int totalAttempts = 0;

    /** Running total of distinct brute force alerts raised since the last reset. */
    private int totalAlerts = 0;

    /**
     * Set of IP addresses that have been blocked after exceeding the threshold.
     * Uses HashSet for O(1) contains() checks on every logAttemptForIP() call.
     */
    private final Set<String> blockedIPs = new HashSet<>();

    // ── UI State ──────────────────────────────────────────────────────────────

    /** Text field where the user types the IP address to log an attempt for. */
    private TextField ipField;

    /** Spinner for configuring THRESHOLD (1–50, default 5). */
    private Spinner<Integer> thresholdSpinner;

    /** Spinner for configuring TIME_WINDOW in seconds (1–120, default 10). */
    private Spinner<Integer> windowSpinner;

    /** Scrollable monospaced text area displaying timestamped event log entries. */
    private TextArea logArea;

    /** Live stat labels — big number displays on the four dashboard cards. */
    private Label statTotal, statIPs, statAlerts, statBlocked;

    /** Secondary stat labels — session delta subtitles beneath the big numbers. */
    private Label statTotalSub, statIPsSub, statAlertsSub, statBlockedSub;

    /** JavaFX TableView displaying live IP watchlist data bound to tableData. */
    private TableView<IPEntry> table;

    /**
     * Observable list backing the TableView. JavaFX automatically updates the table
     * whenever this list is modified (add, remove, clear).
     */
    private ObservableList<IPEntry> tableData = FXCollections.observableArrayList();

    /**
     * Data series for the attempt frequency bar chart.
     * Maintains 12 rolling slots, each representing a recent batch of attempts.
     */
    private XYChart.Series<String, Number> barSeries = new XYChart.Series<>();

    /** Rolling index tracking the current bar chart slot (0–11, wraps around). */
    private int barSlot = 0;

    /** Animated green circle in the sidebar indicating the system is running. */
    private Circle statusDot;

    // ── Dashboard colour palette ──────────────────────────────────────────────

    /** Main content area background — deep navy. */
    private static final String BG_MAIN    = "#0f1629";

    /** Sidebar and top bar background — slightly darker navy. */
    private static final String BG_SIDEBAR = "#0b1020";

    /** Card/panel background — medium dark navy. */
    private static final String BG_CARD    = "#161e35";

    /** Secondary card background — used for alternating table rows and headers. */
    private static final String BG_CARD2   = "#131929";

    /** Border colour for cards, dividers, and table cell borders. */
    private static final String BORDER     = "#1e2d50";

    /** Purple — primary accent colour used for the logo, sidebar icon, Simulate button. */
    private static final String C_PURPLE   = "#8b5cf6";

    /** Cyan — used for Log Attempt button and hit count column. */
    private static final String C_CYAN     = "#06b6d4";

    /** Green — used for CLEAN status badges, INFO log entries, and status dot. */
    private static final String C_GREEN    = "#22c55e";

    /** Red — used for BLOCKED/ATTACK badges, ALERT log entries, Reset button. */
    private static final String C_RED      = "#ef4444";

    /** Amber — used for WATCHING badges and WARN log entries. */
    private static final String C_AMBER    = "#f59e0b";

    /** Blue — used for the Total Attempts stat card accent. */
    private static final String C_BLUE     = "#3b82f6";

    /** Off-white — primary text colour on dark backgrounds. */
    private static final String C_WHITE    = "#f1f5f9";

    /** Muted grey — secondary text, labels, disabled icons. */
    private static final String C_MUTED    = "#64748b";

    /** Dim navy — used for very low-contrast decorative elements. */
    private static final String C_DIM      = "#1e2d50";

    // ══════════════════════════════════════════════════════════════════════════
    // INNER CLASS: IPEntry — TableView data model
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Observable data model for a single row in the IP Watchlist TableView.
     *
     * <p>Uses JavaFX {@code SimpleStringProperty} for all fields so the TableView
     * can bind to them and auto-update when values change via {@code PropertyValueFactory}.</p>
     *
     * <p>Fields correspond to the three table columns:
     * IP Address | Hits / Window | Status</p>
     */
    public static class IPEntry {

        /** IP address string (e.g. "192.168.1.50"). Bound to the "IP ADDRESS" column. */
        private final javafx.beans.property.SimpleStringProperty ip;

        /**
         * Hit count display string (e.g. "4 / 5").
         * Format: {count within current window} / {THRESHOLD}.
         * Bound to the "HITS / WINDOW" column.
         */
        private final javafx.beans.property.SimpleStringProperty hits;

        /**
         * Current threat status of this IP. One of:
         * <ul>
         *   <li>CLEAN    — below 60% of threshold</li>
         *   <li>WATCHING — 60–99% of threshold</li>
         *   <li>ATTACK   — at or above threshold (first detection)</li>
         *   <li>BLOCKED  — previously alerted, all subsequent attempts logged here</li>
         * </ul>
         * Bound to the "STATUS" column.
         */
        private final javafx.beans.property.SimpleStringProperty status;

        /**
         * Constructs an IPEntry with the given IP, hit count string, and status.
         *
         * @param ip     the IP address string
         * @param hits   the formatted hit count string (e.g. "3 / 5")
         * @param status the threat status string (CLEAN / WATCHING / ATTACK / BLOCKED)
         */
        public IPEntry(String ip, String hits, String status) {
            this.ip     = new javafx.beans.property.SimpleStringProperty(ip);
            this.hits   = new javafx.beans.property.SimpleStringProperty(hits);
            this.status = new javafx.beans.property.SimpleStringProperty(status);
        }

        /** @return the IP address string for this entry */
        public String getIp()     { return ip.get(); }

        /** @return the formatted hit count string for this entry */
        public String getHits()   { return hits.get(); }

        /** @return the current status string for this entry */
        public String getStatus() { return status.get(); }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // APPLICATION ENTRY POINT
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * JavaFX application entry point. Builds the root scene graph, starts the
     * 1-second refresh ticker, and starts the status dot blink animation.
     *
     * <p>Layout structure:</p>
     * <pre>
     * BorderPane (root)
     * ├── LEFT  : buildSidebar()   — icon navigation strip
     * ├── TOP   : buildTopBar()    — controls (IP, threshold, window, buttons)
     * └── CENTER: buildDashboard() — stat cards, chart+table, event log
     * </pre>
     *
     * @param stage the primary JavaFX stage provided by the platform
     */
    @Override
    public void start(Stage stage) {
        stage.setTitle("BFDetect — Network Threat Monitor");

        // Root layout: sidebar left, top bar, main dashboard centre
        BorderPane root = new BorderPane();
        root.setStyle("-fx-background-color: " + BG_MAIN + ";");

        root.setLeft(buildSidebar());
        root.setTop(buildTopBar());
        root.setCenter(buildDashboard());

        Scene scene = new Scene(root, 1200, 760);
        scene.getStylesheets().add("data:text/css," + buildCSS());
        stage.setScene(scene);
        stage.setMinWidth(1000);
        stage.setMinHeight(640);
        stage.show();

        // Tick clock — prune expired timestamps and refresh table every second.
        // This ensures IPs revert to CLEAN even when no new attempts arrive.
        Timeline ticker = new Timeline(new KeyFrame(Duration.seconds(1), e -> refreshTable()));
        ticker.setCycleCount(Animation.INDEFINITE);
        ticker.play();

        // Blink animation — pulses the green status dot to indicate the system is live.
        Timeline blink = new Timeline(
            new KeyFrame(Duration.millis(0),   e -> statusDot.setFill(Color.web(C_GREEN))),
            new KeyFrame(Duration.millis(800), e -> statusDot.setFill(Color.web(C_GREEN, 0.2)))
        );
        blink.setCycleCount(Animation.INDEFINITE);
        blink.setAutoReverse(true);
        blink.play();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // UI BUILDERS
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Builds the left navigation sidebar.
     *
     * <p>Contains a logo label, decorative navigation icons, an expandable spacer,
     * the animated status dot (green = running), and a settings icon at the bottom.</p>
     *
     * @return a styled {@code VBox} representing the sidebar
     */
    private VBox buildSidebar() {
        VBox sb = new VBox(4);
        sb.setPrefWidth(52);
        sb.setStyle("-fx-background-color: " + BG_SIDEBAR + "; -fx-border-color: " + BORDER + "; -fx-border-width: 0 1 0 0;");
        sb.setAlignment(Pos.TOP_CENTER);
        sb.setPadding(new Insets(16, 0, 16, 0));

        // Logo icon — decorative hexagonal symbol representing the app brand
        Label logo = new Label("⬡");
        logo.setStyle("-fx-font-size: 22px; -fx-text-fill: " + C_PURPLE + "; -fx-font-weight: bold;");
        sb.getChildren().add(logo);

        sb.getChildren().add(spacer(20));

        // Nav icons — decorative navigation symbols; first icon is highlighted as active
        String[] icons = {"⊞", "◈", "⊕", "◉", "▤", "☰", "◫"};
        for (int i = 0; i < icons.length; i++) {
            Label nav = new Label(icons[i]);
            nav.setPadding(new Insets(10, 0, 10, 0));
            // First icon (dashboard) is highlighted in purple; others are muted
            nav.setStyle("-fx-font-size: 16px; -fx-text-fill: " + (i == 0 ? C_PURPLE : C_MUTED) + ";");
            sb.getChildren().add(nav);
        }

        // Flexible spacer — pushes status dot and settings to the bottom
        Region spacer = new Region();
        VBox.setVgrow(spacer, Priority.ALWAYS);
        sb.getChildren().add(spacer);

        // Status dot — animated circle indicating the detection engine is active
        statusDot = new Circle(6, Color.web(C_GREEN));
        sb.getChildren().add(statusDot);

        // Settings icon
        Label settings = new Label("⚙");
        settings.setPadding(new Insets(10, 0, 0, 0));
        settings.setStyle("-fx-font-size: 16px; -fx-text-fill: " + C_MUTED + ";");
        sb.getChildren().add(settings);

        return sb;
    }

    /**
     * Builds the top navigation/control bar.
     *
     * <p>Left side contains the IP input field and configuration spinners.
     * Right side contains the three action buttons and decorative user icons.</p>
     *
     * @return a styled {@code HBox} representing the top bar
     */
    private HBox buildTopBar() {
        HBox bar = new HBox(12);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.setPadding(new Insets(10, 16, 10, 16));
        bar.setStyle("-fx-background-color: " + BG_SIDEBAR + "; -fx-border-color: " + BORDER + "; -fx-border-width: 0 0 1 0;");

        // Search icon — decorative, positioned next to the IP input field
        Label searchIcon = new Label("🔍");
        searchIcon.setStyle("-fx-text-fill: " + C_MUTED + ";");

        // IP address input — the target IP for manual log attempts
        ipField = new TextField("192.168.1.50");
        ipField.setPromptText("Enter IP address...");
        ipField.getStyleClass().add("cyber-field");
        ipField.setPrefWidth(170);

        // Threshold spinner — sets THRESHOLD (min attempts to trigger an alert)
        Label tLbl = topLabel("Threshold:");
        thresholdSpinner = new Spinner<>(1, 50, 5);
        thresholdSpinner.getStyleClass().add("cyber-spinner");
        thresholdSpinner.setPrefWidth(70);
        thresholdSpinner.setEditable(true); // Allow manual typing

        // Window spinner — sets TIME_WINDOW in seconds (converted to ms internally)
        Label wLbl = topLabel("Window(s):");
        windowSpinner = new Spinner<>(1, 120, 10);
        windowSpinner.getStyleClass().add("cyber-spinner");
        windowSpinner.setPrefWidth(70);
        windowSpinner.setEditable(true);

        // Flexible spacer — pushes action buttons to the right side
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        // Action buttons — each wired to the corresponding handler method
        Button logBtn      = actionBtn("Log Attempt",     C_CYAN);
        Button simulateBtn = actionBtn("Simulate Attack", C_PURPLE);
        Button resetBtn    = actionBtn("Reset",           C_RED);

        logBtn.setOnAction(e -> logAttempt());
        simulateBtn.setOnAction(e -> simulateAttack());
        resetBtn.setOnAction(e -> resetAll());

        // Decorative user icons on the far right
        Label bell = topIcon("🔔");
        Label grid = topIcon("⊞");
        Label user = topIcon("👤");

        bar.getChildren().addAll(searchIcon, ipField,
                tLbl, thresholdSpinner, wLbl, windowSpinner,
                spacer, logBtn, simulateBtn, resetBtn,
                new Separator(Orientation.VERTICAL), bell, grid, user);
        return bar;
    }

    /**
     * Builds the main dashboard area containing three rows:
     * <ol>
     *   <li>Stat cards row ({@link #buildStatCards()})</li>
     *   <li>Bar chart + IP watchlist table ({@link #buildMiddleRow()})</li>
     *   <li>Event log panel ({@link #buildBottomLog()})</li>
     * </ol>
     *
     * @return a styled {@code VBox} containing the full dashboard layout
     */
    private VBox buildDashboard() {
        VBox dash = new VBox(12);
        dash.setPadding(new Insets(14));
        dash.setStyle("-fx-background-color: " + BG_MAIN + ";");

        dash.getChildren().addAll(
            buildStatCards(),
            buildMiddleRow(),
            buildBottomLog()
        );
        // Allow the middle row (chart + table) to grow vertically to fill available space
        VBox.setVgrow(buildMiddleRow(), Priority.ALWAYS);
        return dash;
    }

    /**
     * Builds the top row of four metric stat cards:
     * Total Attempts | Unique IPs | Alerts Fired | Blocked IPs.
     *
     * <p>Each card has a coloured left accent bar, a large number label,
     * and a secondary subtitle label showing the session count.</p>
     *
     * @return an {@code HBox} containing the four stat cards with equal widths
     */
    private HBox buildStatCards() {
        HBox row = new HBox(12);
        row.setPrefHeight(110);

        // Initialise the large number labels (updated by updateStats())
        statTotal   = bigNum("0", C_WHITE);
        statIPs     = bigNum("0", C_WHITE);
        statAlerts  = bigNum("0", C_AMBER);
        statBlocked = bigNum("0", C_RED);

        // Initialise the subtitle delta labels
        statTotalSub   = subLbl("0  (session)");
        statIPsSub     = subLbl("0  (session)");
        statAlertsSub  = subLbl("0  (session)");
        statBlockedSub = subLbl("0  (session)");

        // Build each card with its title, value label, subtitle, accent colour, and icon
        HBox c1 = statCard("TOTAL ATTEMPTS", statTotal,   statTotalSub,   C_BLUE,   "📊");
        HBox c2 = statCard("UNIQUE IPs",     statIPs,     statIPsSub,     C_CYAN,   "🌐");
        HBox c3 = statCard("ALERTS FIRED",   statAlerts,  statAlertsSub,  C_AMBER,  "⚠");
        HBox c4 = statCard("BLOCKED IPs",    statBlocked, statBlockedSub, C_RED,    "🚫");

        // Make each card expand equally to fill the row width
        for (HBox c : new HBox[]{c1, c2, c3, c4}) {
            HBox.setHgrow(c, Priority.ALWAYS);
        }
        row.getChildren().addAll(c1, c2, c3, c4);
        return row;
    }

    /**
     * Builds a single metric stat card.
     *
     * <p>Card layout: [coloured accent bar] | [title row (label + icon)] / [big value] / [subtitle]</p>
     *
     * @param title   the card heading (e.g. "TOTAL ATTEMPTS")
     * @param valLbl  the large number {@code Label} to display
     * @param subLbl  the smaller subtitle {@code Label} to display below the number
     * @param accent  the hex colour string for the left accent bar and arrow icon
     * @param icon    the emoji icon displayed in the top-right of the card
     * @return a styled {@code HBox} representing the stat card
     */
    private HBox statCard(String title, Label valLbl, Label subLbl, String accent, String icon) {
        HBox card = new HBox();
        card.setStyle("-fx-background-color: " + BG_CARD + "; -fx-background-radius: 8; -fx-border-color: " + BORDER + "; -fx-border-radius: 8; -fx-border-width: 1;");

        // Left accent bar — a thin coloured rectangle matching the card's theme colour
        Rectangle bar = new Rectangle(4, 0);
        bar.setFill(Color.web(accent));
        bar.heightProperty().bind(card.heightProperty()); // Stretch to full card height

        VBox content = new VBox(4);
        content.setPadding(new Insets(14, 16, 14, 14));
        content.setAlignment(Pos.TOP_LEFT);
        HBox.setHgrow(content, Priority.ALWAYS);

        // Top row: title label on the left, icon on the right
        HBox topRow = new HBox();
        topRow.setAlignment(Pos.CENTER_LEFT);
        Label titleLbl = new Label(title);
        titleLbl.setStyle("-fx-text-fill: " + C_MUTED + "; -fx-font-size: 10px; -fx-font-weight: bold;");
        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);
        Label iconLbl = new Label(icon);
        iconLbl.setStyle("-fx-font-size: 16px;");
        topRow.getChildren().addAll(titleLbl, sp, iconLbl);

        // Bottom row: up-arrow in accent colour followed by the subtitle delta label
        HBox bottomRow = new HBox(4);
        bottomRow.setAlignment(Pos.CENTER_LEFT);
        Label arrow = new Label("↑ ");
        arrow.setStyle("-fx-text-fill: " + accent + "; -fx-font-size: 11px;");
        bottomRow.getChildren().addAll(arrow, subLbl);

        content.getChildren().addAll(topRow, valLbl, bottomRow);
        card.getChildren().addAll(bar, content);
        return card;
    }

    /**
     * Builds the middle dashboard row containing two side-by-side cards:
     * <ol>
     *   <li><b>Attempt Frequency Bar Chart</b> — a rolling 12-slot bar chart updated
     *       on every attempt via {@link #barSeries}</li>
     *   <li><b>IP Watchlist TableView</b> — a live table bound to {@link #tableData}
     *       showing IP, hit count, and colour-coded status badge per row</li>
     * </ol>
     *
     * @return an {@code HBox} containing both cards with equal widths
     */
    private HBox buildMiddleRow() {
        HBox row = new HBox(12);
        VBox.setVgrow(row, Priority.ALWAYS);

        // ── Bar chart card ───────────────────────────────────────────────────
        VBox chartCard = darkCard();
        HBox.setHgrow(chartCard, Priority.ALWAYS);
        Label chartTitle = cardTitle("ATTEMPT FREQUENCY");

        // Configure axes with muted tick labels and hidden minor ticks
        CategoryAxis xAxis = new CategoryAxis();
        NumberAxis   yAxis = new NumberAxis();
        xAxis.setTickLabelFill(Color.web(C_MUTED));
        xAxis.setTickLabelFont(Font.font("Segoe UI", 9));
        xAxis.setStyle("-fx-tick-line-visible: false; -fx-minor-tick-visible: false;");
        yAxis.setTickLabelFill(Color.web(C_MUTED));
        yAxis.setTickLabelFont(Font.font("Segoe UI", 9));
        yAxis.setStyle("-fx-tick-line-visible: false; -fx-minor-tick-visible: false;");
        yAxis.setMinorTickVisible(false);

        BarChart<String, Number> chart = new BarChart<>(xAxis, yAxis);
        chart.setLegendVisible(false);
        chart.setAnimated(false); // Disable animation for performance
        chart.setBarGap(2);
        chart.setCategoryGap(6);
        chart.setStyle("-fx-background-color: transparent; -fx-plot-background-color: transparent;");
        chart.getData().add(barSeries);

        // Pre-fill 12 empty slot entries so the chart renders immediately on launch
        for (int i = 1; i <= 12; i++)
            barSeries.getData().add(new XYChart.Data<>(String.valueOf(i), 0));
        VBox.setVgrow(chart, Priority.ALWAYS);

        chartCard.getChildren().addAll(chartTitle, chart);

        // ── IP Watchlist table card ──────────────────────────────────────────
        VBox tableCard = darkCard();
        HBox.setHgrow(tableCard, Priority.ALWAYS);

        // Table card header with "LIVE ●" indicator on the right
        HBox tableHeader = new HBox();
        tableHeader.setAlignment(Pos.CENTER_LEFT);
        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);
        Label live = new Label("LIVE ●");
        live.setStyle("-fx-text-fill: " + C_GREEN + "; -fx-font-size: 10px; -fx-font-family: Monospaced;");
        tableHeader.getChildren().addAll(cardTitle("IP WATCHLIST"), sp, live);

        // TableView bound to the observable tableData list
        table = new TableView<>(tableData);
        table.setStyle("-fx-background-color: transparent; -fx-table-cell-border-color: " + BORDER + ";");
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        VBox.setVgrow(table, Priority.ALWAYS);

        // Column: IP Address — bound to IPEntry.ip via PropertyValueFactory
        TableColumn<IPEntry, String> colIP = new TableColumn<>("IP ADDRESS");
        colIP.setCellValueFactory(new PropertyValueFactory<>("ip"));
        colIP.setStyle("-fx-text-fill: " + C_WHITE + ";");

        // Column: Hits / Window — bound to IPEntry.hits, centred
        TableColumn<IPEntry, String> colHits = new TableColumn<>("HITS / WINDOW");
        colHits.setCellValueFactory(new PropertyValueFactory<>("hits"));
        colHits.setStyle("-fx-alignment: CENTER;");

        // Column: Status — bound to IPEntry.status with custom badge cell factory
        TableColumn<IPEntry, String> colStatus = new TableColumn<>("STATUS");
        colStatus.setCellValueFactory(new PropertyValueFactory<>("status"));
        colStatus.setStyle("-fx-alignment: CENTER;");

        // Custom cell factory — renders each status as a coloured rounded badge label
        colStatus.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) { setText(null); setGraphic(null); return; }
                Label badge = new Label(item);
                badge.setPadding(new Insets(2, 10, 2, 10));
                // Apply colour-coded badge style based on status value
                badge.setStyle("-fx-font-weight: bold; -fx-font-size: 11px; -fx-background-radius: 4; " +
                    switch (item) {
                        case "BLOCKED", "ATTACK" -> "-fx-text-fill: " + C_RED   + "; -fx-background-color: #501414;";
                        case "WATCHING"          -> "-fx-text-fill: " + C_AMBER + "; -fx-background-color: #46300a;";
                        default                  -> "-fx-text-fill: " + C_GREEN + "; -fx-background-color: #0f3219;";
                    });
                setGraphic(badge);
                setText(null);
                setAlignment(Pos.CENTER);
            }
        });

        table.getColumns().addAll(colIP, colHits, colStatus);
        tableCard.getChildren().addAll(tableHeader, table);

        row.getChildren().addAll(chartCard, tableCard);
        return row;
    }

    /**
     * Builds the bottom full-width event log card.
     *
     * <p>Contains a non-editable {@code TextArea} with monospaced font that
     * auto-scrolls to the latest entry. All detection events are appended here
     * via {@link #appendLog(String, String)}.</p>
     *
     * @return a styled {@code VBox} card containing the log TextArea
     */
    private VBox buildBottomLog() {
        VBox card = darkCard();
        card.setPrefHeight(180);

        // Header row with "auto-scroll ●" indicator on the right
        HBox header = new HBox();
        header.setAlignment(Pos.CENTER_LEFT);
        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);
        Label autoScroll = new Label("auto-scroll ●");
        autoScroll.setStyle("-fx-text-fill: " + C_GREEN + "; -fx-font-size: 10px; -fx-font-family: Monospaced;");
        header.getChildren().addAll(cardTitle("LAST EVENTS"), sp, autoScroll);

        // Log area — read-only, monospaced, wraps text, grows vertically
        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setWrapText(true);
        logArea.setStyle("-fx-control-inner-background: " + BG_CARD + "; -fx-text-fill: " + C_WHITE +
                         "; -fx-font-family: Monospaced; -fx-font-size: 11px; -fx-border-color: transparent;");
        VBox.setVgrow(logArea, Priority.ALWAYS);

        card.getChildren().addAll(header, logArea);
        return card;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CORE DETECTION ALGORITHM
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Core detection method — processes one failed login attempt from the given IP.
     *
     * <p>Implements the four-step sliding window algorithm:</p>
     * <ol>
     *   <li><b>HashMap insert</b> — O(1) avg: ensures the IP has an entry in loginAttempts</li>
     *   <li><b>Timestamp append</b> — O(1): adds current time to the LinkedList tail</li>
     *   <li><b>Window expiry</b> — amortised O(1): removes timestamps older than TIME_WINDOW
     *       from the LinkedList head</li>
     *   <li><b>Threshold check</b> — O(1): compares list size to THRESHOLD and raises
     *       alert if exceeded</li>
     * </ol>
     *
     * <p>Additionally updates the rolling bar chart slot and calls
     * {@link #updateStats()} and {@link #refreshTable()}.</p>
     *
     * @param ip the IP address string from which the failed attempt originated
     */
    private void logAttemptForIP(String ip) {
        long now = System.currentTimeMillis();

        // Read live values from the GUI spinners so changes take immediate effect
        THRESHOLD   = thresholdSpinner.getValue();
        TIME_WINDOW = windowSpinner.getValue() * 1000L;

        // 1. If IP isn't in map, add it (SEN2212 HashMap O(1) lookup)
        loginAttempts.putIfAbsent(ip, new LinkedList<>());

        // 2. Get the history (SEN2211 LinkedList/Queue) and append new timestamp
        LinkedList<Long> ts = loginAttempts.get(ip);
        ts.addLast(now);

        // 3. Remove old timestamps outside the window (Sliding Window logic)
        // Each timestamp is removed at most once → amortised O(1) over the sequence
        while (!ts.isEmpty() && (now - ts.peekFirst() > TIME_WINDOW))
            ts.removeFirst();

        totalAttempts++;

        // Update bar chart — increment the current rolling slot and advance the pointer
        int last = barSlot % 12;
        XYChart.Data<String, Number> slot = barSeries.getData().get(last);
        slot.setYValue(((Number) slot.getYValue()).intValue() + 1);
        barSlot++;

        // 4. Check for attack
        // Thresholds: 5 fails within 10 seconds (10,000 milliseconds)
        int count = ts.size();
        String time = new SimpleDateFormat("HH:mm:ss").format(new Date());

        if (count >= THRESHOLD) {
            if (!blockedIPs.contains(ip)) {
                // First time this IP crosses the threshold — raise primary alert
                totalAlerts++;
                blockedIPs.add(ip); // O(1) HashSet insert
                appendLog(time + "   [ALERT]   BRUTE FORCE from " + ip + " — " + count + " hits in window", C_RED);
            } else {
                // IP already blocked — log continued attempts without re-alerting
                appendLog(time + "   [BLOCKED] continued attempt from " + ip + " (" + count + " hits)", C_RED);
            }
        } else if (count >= Math.ceil(THRESHOLD * 0.6)) {
            // 60–99% of threshold — suspicious but not yet an attack
            appendLog(time + "   [WARN]    suspicious: " + ip + " — " + count + "/" + THRESHOLD + " hits", C_AMBER);
        } else {
            // Below 60% of threshold — normal activity
            appendLog(time + "   [INFO]    attempt logged " + ip + " — " + count + "/" + THRESHOLD, C_GREEN);
        }

        updateStats();
        refreshTable();
    }

    /**
     * Reads the IP from the input field and logs one attempt for it.
     * Called when the "Log Attempt" button is pressed.
     * Does nothing if the IP field is empty.
     */
    private void logAttempt() {
        String ip = ipField.getText().trim();
        if (ip.isEmpty()) return;
        logAttemptForIP(ip);
    }

    /**
     * Runs the attack simulation — mirrors the original {@code main()} method logic.
     *
     * <p>Sequence:</p>
     * <ol>
     *   <li>Logs an immediate attempt from "192.168.1.50" (Attacker 1)</li>
     *   <li>Logs an immediate attempt from "10.0.0.1" (a different user)</li>
     *   <li>Fires 6 rapid attempts at 400 ms intervals from the entered IP
     *       using a non-blocking {@code JavaFX Timeline} (replacing Thread.sleep)</li>
     * </ol>
     *
     * <p>With default settings (threshold=5, window=10s), attempts 1–2 log as INFO,
     * attempts 3–4 as WARN, and attempt 5+ trigger ALERT → BLOCKED.</p>
     */
    private void simulateAttack() {
        // Mirrors the original main() — simulates 6+ quick failed attempts from attacker IP
        String ip = ipField.getText().trim().isEmpty() ? "192.168.1.50" : ipField.getText().trim();
        appendLog("──────────────────────────────────────────────────", C_MUTED);
        appendLog("[ SIMULATION ] target: " + ip, C_MUTED);

        // Inside your main method, try adding this:
        logAttemptForIP("192.168.1.50"); // Attacker 1
        logAttemptForIP("10.0.0.1");     // A different user

        // Simulate 6 quick failed attempts (JavaFX Timeline replaces Thread.sleep)
        Timeline sim = new Timeline();
        for (int i = 0; i < 6; i++) { // Stop after 6 attempts
            final String target = ip;
            sim.getKeyFrames().add(
                new KeyFrame(Duration.millis(400L * (i + 1)), e -> logAttemptForIP(target))
            );
        }
        sim.play();
    }

    /**
     * Resets the entire detection engine and clears all UI state.
     *
     * <p>Clears: loginAttempts map, blockedIPs set, all counters, bar chart data,
     * log area, table data, and all stat labels back to "0".</p>
     */
    private void resetAll() {
        loginAttempts.clear();     // Clear all IP tracking data
        blockedIPs.clear();        // Unblock all IPs
        totalAttempts = 0;
        totalAlerts   = 0;
        barSlot = 0;
        // Reset all bar chart slots to 0
        for (XYChart.Data<String, Number> d : barSeries.getData()) d.setYValue(0);
        logArea.clear();
        tableData.clear();
        // Reset all stat display labels
        statTotal.setText("0");   statTotalSub.setText("0  (session)");
        statIPs.setText("0");     statIPsSub.setText("0  (session)");
        statAlerts.setText("0");  statAlertsSub.setText("0  (session)");
        statBlocked.setText("0"); statBlockedSub.setText("0  (session)");
        appendLog("[ SYSTEM RESET ]", C_MUTED);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // UI UPDATE HELPERS
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Refreshes the IP Watchlist TableView with current sliding window data.
     *
     * <p>Called every second by the background ticker {@code Timeline} as well as
     * after every {@link #logAttemptForIP(String)} call. For each tracked IP:</p>
     * <ol>
     *   <li>Prunes timestamps older than TIME_WINDOW using {@code removeIf}</li>
     *   <li>Computes the current hit count within the window</li>
     *   <li>Determines the status: BLOCKED → ATTACK → WATCHING → CLEAN</li>
     *   <li>Adds a new {@code IPEntry} row to the observable tableData list</li>
     * </ol>
     *
     * <p>The passive timestamp pruning here ensures IPs revert from ATTACK to CLEAN
     * after the time window expires, even without new incoming attempts.</p>
     */
    private void refreshTable() {
        long now = System.currentTimeMillis();
        tableData.clear(); // Rebuild from scratch on every tick

        for (Map.Entry<String, LinkedList<Long>> e : loginAttempts.entrySet()) {
            String ip = e.getKey();
            LinkedList<Long> ts = e.getValue();

            // Passively prune expired timestamps — this is the background expiry mechanism
            ts.removeIf(t -> now - t > TIME_WINDOW);

            int count = ts.size();

            // Determine status in priority order: blocked overrides all
            String status = blockedIPs.contains(ip)                   ? "BLOCKED"
                          : count >= THRESHOLD                         ? "ATTACK"
                          : count >= (int) Math.ceil(THRESHOLD * 0.6) ? "WATCHING"
                          : "CLEAN";

            tableData.add(new IPEntry(ip, count + " / " + THRESHOLD, status));
        }
        updateStats();
    }

    /**
     * Updates all four stat card labels with current session counts.
     * Called after every detection event and every table refresh tick.
     */
    private void updateStats() {
        statTotal.setText(String.valueOf(totalAttempts));
        statIPs.setText(String.valueOf(loginAttempts.size()));
        statAlerts.setText(String.valueOf(totalAlerts));
        statBlocked.setText(String.valueOf(blockedIPs.size()));
        statTotalSub.setText(totalAttempts + "  (session)");
        statIPsSub.setText(loginAttempts.size() + "  (session)");
        statAlertsSub.setText(totalAlerts + "  (session)");
        statBlockedSub.setText(blockedIPs.size() + "  (session)");
    }

    /**
     * Appends a timestamped message to the event log TextArea.
     *
     * <p>Uses {@code Platform.runLater()} to ensure the UI update runs on the
     * JavaFX Application Thread, even if called from a background timeline.</p>
     *
     * @param msg   the log message to append (a newline is added automatically)
     * @param color the hex colour string for visual categorisation (unused in text
     *              mode — the TextArea renders all text uniformly; colour is used
     *              semantically by callers to distinguish severity levels)
     */
    private void appendLog(String msg, String color) {
        Platform.runLater(() -> logArea.appendText(msg + "\n"));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // WIDGET FACTORY HELPERS
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Creates a styled dark card VBox used as the container for each dashboard panel.
     *
     * <p>Applied style: dark navy background, rounded 8px corners, thin border.</p>
     *
     * @return a styled {@code VBox} ready to receive child content
     */
    private VBox darkCard() {
        VBox card = new VBox(10);
        card.setStyle("-fx-background-color: " + BG_CARD +
                      "; -fx-background-radius: 8; -fx-border-color: " + BORDER +
                      "; -fx-border-radius: 8; -fx-border-width: 1; -fx-padding: 14;");
        return card;
    }

    /**
     * Creates a small uppercase muted label used as a card section title.
     *
     * @param text the title text (typically all-caps)
     * @return a styled {@code Label}
     */
    private Label cardTitle(String text) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: " + C_MUTED + "; -fx-font-size: 10px; -fx-font-weight: bold;");
        return l;
    }

    /**
     * Creates a large bold number label used for stat card values.
     *
     * @param text  the initial text (e.g. "0")
     * @param color the hex colour string for the text
     * @return a styled {@code Label} with 30px bold font
     */
    private Label bigNum(String text, String color) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: " + color + "; -fx-font-size: 30px; -fx-font-weight: bold;");
        return l;
    }

    /**
     * Creates a small muted subtitle label used below stat card values.
     *
     * @param text the subtitle text (e.g. "0  (session)")
     * @return a styled {@code Label} with 11px muted text
     */
    private Label subLbl(String text) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: " + C_MUTED + "; -fx-font-size: 11px;");
        return l;
    }

    /**
     * Creates a small muted label used for field labels in the top bar.
     *
     * @param text the label text (e.g. "Threshold:")
     * @return a styled {@code Label}
     */
    private Label topLabel(String text) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: " + C_MUTED + "; -fx-font-size: 11px;");
        return l;
    }

    /**
     * Creates a decorative icon label used in the top bar's right section.
     *
     * @param icon the emoji or symbol to display
     * @return a styled {@code Label} with hand cursor on hover
     */
    private Label topIcon(String icon) {
        Label l = new Label(icon);
        l.setStyle("-fx-text-fill: " + C_MUTED + "; -fx-font-size: 14px; -fx-cursor: hand;");
        return l;
    }

    /**
     * Creates a fixed-height invisible spacer region.
     *
     * @param h the preferred height in pixels
     * @return a {@code Region} with the specified preferred height
     */
    private Region spacer(double h) {
        Region r = new Region();
        r.setPrefHeight(h);
        return r;
    }

    /**
     * Creates a styled action button with a transparent background and coloured border/text.
     * The background brightens slightly on mouse hover for visual feedback.
     *
     * @param text  the button label text
     * @param color the hex colour string used for text, border, and hover background
     * @return a styled {@code Button} with hover effect
     */
    private Button actionBtn(String text, String color) {
        Button b = new Button(text);
        b.setStyle("-fx-background-color: transparent; -fx-text-fill: " + color +
                   "; -fx-border-color: " + color + "; -fx-border-radius: 6; -fx-background-radius: 6;" +
                   "-fx-font-size: 11px; -fx-font-weight: bold; -fx-cursor: hand; -fx-padding: 5 14 5 14;");
        // On hover: add a semi-transparent fill of the accent colour (33 = 20% opacity in hex)
        b.setOnMouseEntered(e -> b.setStyle(b.getStyle().replace("transparent", color + "33")));
        b.setOnMouseExited(e  -> b.setStyle(b.getStyle().replace(color + "33", "transparent")));
        return b;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CSS STYLESHEET
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Returns the inline CSS stylesheet injected into the scene via a data URI.
     *
     * <p>Styles targeted: cyber-field (IP input), cyber-spinner (threshold/window
     * spinners), table-view rows and headers, bar-chart colours, text-area,
     * and scrollbar thumbs throughout the dashboard.</p>
     *
     * @return a CSS string compatible with JavaFX scene stylesheets
     */
    private String buildCSS() {
        return
            // IP input field — dark navy background, light text, no visible focus ring
            ".cyber-field { -fx-background-color: #1e2a4a; -fx-text-fill: #f1f5f9; -fx-border-color: #1e2d50; " +
            "  -fx-border-radius: 4; -fx-background-radius: 4; -fx-font-size: 12px; -fx-prompt-text-fill: #64748b; }" +
            // Spinner text field and arrow buttons
            ".cyber-spinner .text-field { -fx-background-color: #1e2a4a; -fx-text-fill: #f1f5f9; " +
            "  -fx-border-color: #1e2d50; -fx-font-size: 12px; }" +
            ".cyber-spinner .increment-arrow-button, .cyber-spinner .decrement-arrow-button { " +
            "  -fx-background-color: #1e2a4a; }" +
            ".cyber-spinner .increment-arrow, .cyber-spinner .decrement-arrow { -fx-background-color: #64748b; }" +
            // TableView — transparent background, custom row colours
            ".table-view { -fx-background-color: transparent; -fx-border-color: transparent; }" +
            ".table-view .column-header { -fx-background-color: #131929; -fx-border-color: #1e2d50; -fx-border-width: 0 0 1 0; }" +
            ".table-view .column-header .label { -fx-text-fill: #64748b; -fx-font-size: 10px; -fx-font-weight: bold; -fx-alignment: CENTER-LEFT; }" +
            ".table-view .table-row-cell { -fx-background-color: #161e35; -fx-border-color: #1e2d50; -fx-border-width: 0 0 1 0; -fx-text-fill: #f1f5f9; }" +
            ".table-view .table-row-cell:odd { -fx-background-color: #131929; }" +       // Alternating row colour
            ".table-view .table-row-cell:selected { -fx-background-color: #8b5cf633; }" + // Purple selection tint
            ".table-view .table-cell { -fx-text-fill: #f1f5f9; -fx-font-size: 12px; }" +
            ".table-view .scroll-bar { -fx-background-color: transparent; }" +
            ".table-view .scroll-bar .thumb { -fx-background-color: #1e2d50; -fx-background-radius: 4; }" +
            // Bar chart — purple bars, transparent backgrounds, subtle grid lines
            ".bar-chart .chart-bar { -fx-bar-fill: #8b5cf6; }" +
            ".bar-chart .chart-plot-background { -fx-background-color: transparent; }" +
            ".bar-chart .chart-vertical-grid-lines { -fx-stroke: #1e2d50; }" +
            ".bar-chart .chart-horizontal-grid-lines { -fx-stroke: #1e2d50; }" +
            ".bar-chart { -fx-background-color: transparent; }" +
            // Event log TextArea — dark background, monospaced font
            ".text-area { -fx-background-color: #161e35; -fx-control-inner-background: #161e35; " +
            "  -fx-font-family: Monospaced; -fx-font-size: 11px; -fx-text-fill: #f1f5f9; }" +
            ".text-area .scroll-bar { -fx-background-color: transparent; }" +
            ".text-area .scroll-bar .thumb { -fx-background-color: #1e2d50; -fx-background-radius: 4; }" +
            ".scroll-bar:vertical .track { -fx-background-color: transparent; }" +
            // Separator dividers in the top bar
            ".separator { -fx-background-color: #1e2d50; }";
    }

    // ══════════════════════════════════════════════════════════════════════════
    // ENTRY POINT
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Application entry point. Delegates to {@code Application.launch()} which
     * initialises the JavaFX platform and calls {@link #start(Stage)}.
     *
     * @param args command-line arguments (not used)
     */
    public static void main(String[] args) {
        launch(args);
    }
}
