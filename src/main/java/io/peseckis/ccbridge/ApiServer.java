package io.peseckis.ccbridge;

import burp.api.montoya.MontoyaApi;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.peseckis.ccbridge.auth.TokenManager;
import io.peseckis.ccbridge.handlers.*;
import io.peseckis.ccbridge.util.Json;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

public class ApiServer {

    private final MontoyaApi api;
    private final String host;
    private final int port;
    private final String token;
    private HttpServer http;

    private final HistoryStore historyStore = new HistoryStore();
    private final ScanRegistry scanRegistry;
    private final CollaboratorRegistry collaboratorRegistry;

    public ApiServer(MontoyaApi api, String host, int port, String token) {
        this.api = api;
        this.host = host;
        this.port = port;
        this.token = token;
        this.scanRegistry = new ScanRegistry(api);
        this.collaboratorRegistry = new CollaboratorRegistry(api);
    }

    public void start() throws IOException {
        http = HttpServer.create(new InetSocketAddress(host, port), 0);
        http.setExecutor(Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "cc-bridge-worker");
            t.setDaemon(true);
            return t;
        }));

        Map<String, HttpHandler> routes = new HashMap<>();
        routes.put("/health",           authed(new HealthHandler()));
        routes.put("/send",             authed(new SendHandler(api, historyStore)));
        routes.put("/history",          authed(new HistoryHandler(api, historyStore)));
        routes.put("/history/",         authed(new HistoryItemHandler(api, historyStore)));
        routes.put("/repeat/",          authed(new RepeatHandler(api, historyStore)));
        routes.put("/decode",           authed(new DecodeHandler(api)));
        routes.put("/scan",             authed(new ScanHandler(api, scanRegistry, historyStore)));
        routes.put("/scan/",            authed(new ScanStatusHandler(scanRegistry)));
        routes.put("/issues",           authed(new IssuesHandler(api)));
        routes.put("/collaborator/new", authed(new CollaboratorNewHandler(collaboratorRegistry)));
        routes.put("/collaborator/",    authed(new CollaboratorPollHandler(collaboratorRegistry)));

        for (Map.Entry<String, HttpHandler> e : routes.entrySet()) {
            http.createContext(e.getKey(), e.getValue());
        }
        // Root: usage hint (still requires auth).
        http.createContext("/", authed(this::root));
        http.start();
    }

    public void stop() {
        if (http != null) http.stop(0);
    }

    private void root(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) { Responses.methodNotAllowed(ex); return; }
        Map<String, Object> body = new HashMap<>();
        body.put("name", "cc-bridge");
        body.put("version", "0.1.0");
        body.put("endpoints", new String[]{
                "GET  /health",
                "POST /send                       {method,url,headers,body | raw}",
                "GET  /history?host=&method=&status=&contains=&limit=",
                "GET  /history/{id}",
                "POST /repeat/{id}                {headers?, body?, method?, url?}",
                "POST /decode                     {input, kind:auto|b64|b64url|url|hex|jwt|gzip}",
                "POST /scan                       {url|historyId, type:active|passive}",
                "GET  /scan/{taskId}",
                "GET  /issues?host=&severity=",
                "POST /collaborator/new",
                "GET  /collaborator/{ctx}"
        });
        body.put("time", Instant.now().toString());
        Responses.json(ex, 200, body);
    }

    /** Wraps a handler with bearer-token auth. */
    private HttpHandler authed(HttpHandler next) {
        return ex -> {
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            if (!TokenManager.validate(auth, token)) {
                Map<String, Object> err = new HashMap<>();
                err.put("error", "unauthorized");
                err.put("hint", "send: Authorization: Bearer <token from ~/.cc-bridge-token>");
                Responses.json(ex, 401, err);
                return;
            }
            try {
                next.handle(ex);
            } catch (Throwable t) {
                api.logging().logToError("CC-Bridge handler error: " + t);
                Map<String, Object> err = new HashMap<>();
                err.put("error", "internal");
                err.put("message", String.valueOf(t.getMessage()));
                err.put("type", t.getClass().getSimpleName());
                Responses.json(ex, 500, err);
            } finally {
                ex.close();
            }
        };
    }

    public static class Responses {
        public static void json(HttpExchange ex, int status, Object body) throws IOException {
            byte[] payload = Json.GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            ex.sendResponseHeaders(status, payload.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(payload); }
        }
        public static void text(HttpExchange ex, int status, String body) throws IOException {
            byte[] payload = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            ex.sendResponseHeaders(status, payload.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(payload); }
        }
        public static void methodNotAllowed(HttpExchange ex) throws IOException {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "method_not_allowed");
            err.put("method", ex.getRequestMethod());
            json(ex, 405, err);
        }
    }
}
