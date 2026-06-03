package io.peseckis.ccbridge.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class HistoryHandler implements HttpHandler {

    private final MontoyaApi api;
    private final HistoryStore store;

    public HistoryHandler(MontoyaApi api, HistoryStore store) {
        this.api = api;
        this.store = store;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }

        Map<String, String> q = parseQuery(ex.getRequestURI());
        String hostFilter   = q.get("host");
        String methodFilter = q.get("method");
        String statusFilter = q.get("status");
        String containsAny  = q.get("contains");
        String source       = q.getOrDefault("source", "all"); // proxy | store | all
        int limit = q.containsKey("limit") ? Math.max(1, Math.min(2000, Integer.parseInt(q.get("limit")))) : 200;

        JsonArray out = new JsonArray();
        int kept = 0;

        // --- store entries (issued via /send /repeat) ---
        if (!"proxy".equalsIgnoreCase(source)) {
            List<HistoryStore.Entry> snap = store.snapshot();
            for (int i = snap.size() - 1; i >= 0 && kept < limit; i--) {
                HistoryStore.Entry e = snap.get(i);
                if (!matches(e, hostFilter, methodFilter, statusFilter, containsAny)) continue;
                JsonObject row = SendHandler.RequestBuilder.summarize(e, false);
                row.addProperty("source", "store");
                out.add(row);
                kept++;
            }
        }

        // --- Burp's own proxy history ---
        if (!"store".equalsIgnoreCase(source) && kept < limit) {
            List<ProxyHttpRequestResponse> proxy = api.proxy().history();
            // newest last in Burp's API; iterate reverse
            for (int i = proxy.size() - 1; i >= 0 && kept < limit; i--) {
                ProxyHttpRequestResponse pr = proxy.get(i);
                var req = pr.finalRequest();
                var res = pr.originalResponse();
                String reqHost = req.httpService() != null ? req.httpService().host() : "";
                String method  = req.method();
                int status     = (res != null) ? res.statusCode() : 0;

                if (hostFilter != null && !reqHost.toLowerCase(Locale.ROOT).contains(hostFilter.toLowerCase(Locale.ROOT))) continue;
                if (methodFilter != null && !method.equalsIgnoreCase(methodFilter)) continue;
                if (statusFilter != null && status != safeInt(statusFilter)) continue;
                if (containsAny != null) {
                    String hay = req.toString() + (res != null ? res.toString() : "");
                    if (!hay.contains(containsAny)) continue;
                }
                JsonObject row = new JsonObject();
                row.addProperty("source", "proxy");
                row.addProperty("proxyIndex", i);
                row.addProperty("method", method);
                row.addProperty("host", reqHost);
                row.addProperty("port", req.httpService() != null ? req.httpService().port() : 0);
                row.addProperty("tls", req.httpService() != null && req.httpService().secure());
                row.addProperty("path", req.path());
                row.addProperty("status", status);
                row.addProperty("length", res != null ? res.body().length() : 0);
                out.add(row);
                kept++;
            }
        }

        JsonObject body = new JsonObject();
        body.addProperty("count", kept);
        body.add("items", out);
        ApiServer.Responses.json(ex, 200, body);
    }

    private static boolean matches(HistoryStore.Entry e, String host, String method, String status, String contains) {
        var req = e.rr().request();
        var res = e.rr().response();
        if (host != null) {
            String h = req.httpService() != null ? req.httpService().host() : "";
            if (!h.toLowerCase(Locale.ROOT).contains(host.toLowerCase(Locale.ROOT))) return false;
        }
        if (method != null && !req.method().equalsIgnoreCase(method)) return false;
        if (status != null) {
            int s = res != null ? res.statusCode() : 0;
            if (s != safeInt(status)) return false;
        }
        if (contains != null) {
            String hay = req.toString() + (res != null ? res.toString() : "");
            if (!hay.contains(contains)) return false;
        }
        return true;
    }

    private static int safeInt(String s) { try { return Integer.parseInt(s); } catch (Exception e) { return -1; } }

    public static Map<String, String> parseQuery(URI uri) {
        Map<String, String> map = new HashMap<>();
        String q = uri.getRawQuery();
        if (q == null || q.isBlank()) return map;
        for (String pair : q.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            try {
                map.put(URLDecoder.decode(k, StandardCharsets.UTF_8),
                        URLDecoder.decode(v, StandardCharsets.UTF_8));
            } catch (Exception ignored) {}
        }
        return map;
    }
}
