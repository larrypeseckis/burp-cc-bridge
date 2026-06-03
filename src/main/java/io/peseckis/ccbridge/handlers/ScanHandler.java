package io.peseckis.ccbridge.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;
import io.peseckis.ccbridge.util.Json;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ScanHandler implements HttpHandler {

    private final MontoyaApi api;
    private final ScanRegistry registry;
    private final HistoryStore history;

    public ScanHandler(MontoyaApi api, ScanRegistry registry, HistoryStore history) {
        this.api = api; this.registry = registry; this.history = history;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }
        JsonObject body = Json.parseObject(ex.getRequestBody());

        HttpRequest req = resolveRequest(body);
        if (req == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "bad_request");
            err.put("hint", "Provide one of: {url}, {historyId}, or {method,url,headers,body}");
            ApiServer.Responses.json(ex, 400, err); return;
        }

        String type = Json.getString(body, "type", "active").toLowerCase();
        BuiltInAuditConfiguration cfg = switch (type) {
            case "passive" -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS;
            default        -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS;
        };
        Audit audit;
        try {
            audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(cfg));
        } catch (Throwable t) {
            audit = null;
        }
        if (audit == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "scanner_unavailable");
            err.put("hint", "Burp's audit/scanner API is Professional-only — not available in Burp Community.");
            ApiServer.Responses.json(ex, 501, err);
            return;
        }
        audit.addRequest(req);

        ScanRegistry.Task t = registry.register(audit, Json.getString(body, "label", type + ":" + req.url()));
        JsonObject out = new JsonObject();
        out.addProperty("taskId", t.id());
        out.addProperty("type", type);
        out.addProperty("targetUrl", req.url());
        out.addProperty("createdAt", t.createdAtMillis());
        ApiServer.Responses.json(ex, 200, out);
    }

    private HttpRequest resolveRequest(JsonObject body) {
        // From stored history id
        if (body.has("historyId") && !body.get("historyId").isJsonNull()) {
            long id = body.get("historyId").getAsLong();
            HistoryStore.Entry e = history.get(id);
            return e != null ? e.rr().request() : null;
        }
        // From explicit fields (same shape as /send)
        return SendHandler.RequestBuilder.fromJson(body);
    }
}
