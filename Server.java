import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

/**
 * BFDetect HTTP Server
 *
 * Endpoints:
 *   GET  /login  — serves login.html
 *   POST /login  — authenticates; runs detection on failed attempts
 *   GET  /status — returns live IP state as JSON (for monitor page)
 *
 *
 * Compile:  javac DetectionEngine.java Server.java
 * Run:      java Server
 */
public class Server {

    private static final int    PORT       = 8080;
    private static final String VALID_USER = "admin";
    private static final String VALID_PASS = "password123";

    private static final DetectionEngine engine = new DetectionEngine();

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/login",  Server::handleLogin);
        server.createContext("/status", Server::handleStatus);
        server.setExecutor(null);
        server.start();

        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("  BFDetect server running");
        System.out.printf ("  Login   → http://localhost:%d/login%n",  PORT);
        System.out.printf ("  Monitor → http://localhost:%d/status%n", PORT);
        System.out.println("  Threshold : " + DetectionEngine.THRESHOLD + " attempts");
        System.out.println("  Window    : " + DetectionEngine.WINDOW_MS / 1000 + " seconds");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    private static void handleLogin(HttpExchange ex) throws IOException {
        switch (ex.getRequestMethod().toUpperCase()) {
            case "GET"  -> serveLoginPage(ex);
            case "POST" -> handlePost(ex);
            default     -> send(ex, 405, "text/plain", "Method Not Allowed");
        }
    }

    private static void handleStatus(HttpExchange ex) throws IOException {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        send(ex, 200, "application/json", engine.toJson());
    }

    private static void serveLoginPage(HttpExchange ex) throws IOException {
        Path html = Path.of("login.html");
        if (!Files.exists(html)) {
            send(ex, 404, "text/plain", "login.html not found");
            return;
        }
        byte[] body = Files.readAllBytes(html);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(200, body.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(body); }
    }

    private static void handlePost(HttpExchange ex) throws IOException {
        String ip = ex.getRemoteAddress().getAddress().getHostAddress();

        // Check if block before touching credentials
        if (engine.isBlocked(ip)) {
            engine.logAttempt(ip);
            log("BLOCKED ", ip, "rejected before auth (HTTP 429)");
            send(ex, 429, "text/html", page429());
            return;
        }

        Map<String, String> params = parseForm(
            new String(ex.getRequestBody().readAllBytes())
        );
        String user = params.getOrDefault("username", "");
        String pass = params.getOrDefault("password", "");

        if (VALID_USER.equals(user) && VALID_PASS.equals(pass)) {
            log("SUCCESS ", ip, "login accepted");
            send(ex, 200, "text/html", page200());
            return;
        }

        // Wrong credentials
        engine.logAttempt(ip);
        String status = engine.getStatus(ip);
        log(status, ip, "wrong credentials");

        if (engine.isBlocked(ip)) {
            send(ex, 429, "text/html", page429());
        } else {
            send(ex, 401, "text/html", page401());
        }
    }

    private static void send(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] bytes = body.getBytes();
        ex.getResponseHeaders().set("Content-Type", type + "; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> map = new HashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    map.put(
                        URLDecoder.decode(kv[0], "UTF-8"),
                        URLDecoder.decode(kv[1], "UTF-8")
                    );
                } catch (UnsupportedEncodingException ignored) {}
            }
        }
        return map;
    }

    private static void log(String status, String ip, String msg) {
        System.out.printf("[%-8s]  %-15s  %s%n", status.trim(), ip, msg);
    }

    private static String page401() {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8"/>
              <meta name="viewport" content="width=device-width,initial-scale=1"/>
              <script src="https://cdn.tailwindcss.com"></script>
              <title>401 — Unauthorized</title>
            </head>
            <body class="bg-gray-950 min-h-screen flex items-center justify-center">
              <div class="text-center space-y-3">
                <p class="text-6xl font-bold text-yellow-500">401</p>
                <p class="text-gray-300">Invalid username or password.</p>
                <a href="/login" class="block text-sm text-gray-500 hover:text-gray-300 transition mt-2">← Try again</a>
              </div>
            </body>
            </html>
            """;
    }

    private static String page429() {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8"/>
              <meta name="viewport" content="width=device-width,initial-scale=1"/>
              <script src="https://cdn.tailwindcss.com"></script>
              <title>429 — Blocked</title>
            </head>
            <body class="bg-gray-950 min-h-screen flex items-center justify-center">
              <div class="text-center space-y-3">
                <p class="text-6xl font-bold text-red-500">429</p>
                <p class="text-gray-300">Too many failed attempts.</p>
                <p class="text-sm text-gray-600">Your IP has been blocked. Wait for the detection window to expire.</p>
                <a href="/login" class="block text-sm text-gray-500 hover:text-gray-300 transition mt-2">← Back</a>
              </div>
            </body>
            </html>
            """;
    }

    private static String page200() {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8"/>
              <meta name="viewport" content="width=device-width,initial-scale=1"/>
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Welcome</title>
            </head>
            <body class="bg-gray-950 min-h-screen flex items-center justify-center">
              <div class="text-center space-y-3">
                <p class="text-6xl font-bold text-green-500">200</p>
                <p class="text-gray-300">Login successful. Welcome, admin.</p>
              </div>
            </body>
            </html>
            """;
    }
}
