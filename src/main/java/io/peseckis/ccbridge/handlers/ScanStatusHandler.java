package io.peseckis.ccbridge.handlers;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ScanStatusHandler implements HttpHandler {

    private final ScanRegistry registry;
    public ScanStatusHandler(ScanRegistry registry) { this.registry = registry; }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        String tail = path.substring("/scan/".length());

        if ("DELETE".equalsIgnoreCase(ex.getRequestMethod())) {
            long id; try { id = Long.parseLong(tail); } catch (Exception e) { bad(ex); return; }
            registry.cancel(id);
            JsonObject o = new JsonObject(); o.addProperty("cancelled", id);
            ApiServer.Responses.json(ex, 200, o);
            return;
        }
        if (!"GET".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }

        long id; try { id = Long.parseLong(tail); } catch (Exception e) { bad(ex); return; }
        ScanRegistry.Task t = registry.get(id);
        if (t == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "not_found"); err.put("taskId", id);
            ApiServer.Responses.json(ex, 404, err); return;
        }

        JsonObject out = new JsonObject();
        out.addProperty("taskId", t.id());
        out.addProperty("label", t.label());
        out.addProperty("createdAt", t.createdAtMillis());
        try { out.addProperty("status", t.audit().statusMessage()); } catch (Throwable ignored) {}
        try { out.addProperty("requestCount", t.audit().requestCount()); } catch (Throwable ignored) {}
        try { out.addProperty("errorCount", t.audit().errorCount()); } catch (Throwable ignored) {}
        try { out.addProperty("insertionPointCount", t.audit().insertionPointCount()); } catch (Throwable ignored) {}

        JsonArray issues = new JsonArray();
        try {
            for (AuditIssue iss : t.audit().issues()) issues.add(IssuesHandler.summarize(iss));
        } catch (Throwable ignored) {}
        out.add("issues", issues);
        ApiServer.Responses.json(ex, 200, out);
    }

    private void bad(HttpExchange ex) throws IOException {
        Map<String, Object> err = new HashMap<>();
        err.put("error", "bad_id"); err.put("hint", "GET /scan/{taskId} or DELETE /scan/{taskId}");
        ApiServer.Responses.json(ex, 400, err);
    }
}
