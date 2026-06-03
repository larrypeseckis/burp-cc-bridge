package io.peseckis.ccbridge.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;

public class IssuesHandler implements HttpHandler {

    private final MontoyaApi api;
    public IssuesHandler(MontoyaApi api) { this.api = api; }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }

        Map<String, String> q = HistoryHandler.parseQuery(ex.getRequestURI());
        String hostFilter = q.get("host");
        String sevFilter  = q.get("severity");

        JsonArray arr = new JsonArray();
        int n = 0;
        try {
            for (AuditIssue iss : api.siteMap().issues()) {
                if (hostFilter != null && (iss.baseUrl() == null || !iss.baseUrl().toLowerCase(Locale.ROOT).contains(hostFilter.toLowerCase(Locale.ROOT)))) continue;
                if (sevFilter != null && !iss.severity().name().equalsIgnoreCase(sevFilter)) continue;
                arr.add(summarize(iss));
                n++;
            }
        } catch (Throwable t) {
            JsonObject err = new JsonObject();
            err.addProperty("error", "issues_unavailable");
            err.addProperty("message", String.valueOf(t.getMessage()));
            ApiServer.Responses.json(ex, 500, err); return;
        }
        JsonObject out = new JsonObject();
        out.addProperty("count", n);
        out.add("items", arr);
        ApiServer.Responses.json(ex, 200, out);
    }

    public static JsonObject summarize(AuditIssue iss) {
        JsonObject o = new JsonObject();
        try { o.addProperty("name", iss.name()); } catch (Throwable ignored) {}
        try { o.addProperty("severity", iss.severity().name()); } catch (Throwable ignored) {}
        try { o.addProperty("confidence", iss.confidence().name()); } catch (Throwable ignored) {}
        try { o.addProperty("baseUrl", iss.baseUrl()); } catch (Throwable ignored) {}
        try { o.addProperty("definitionId", iss.definition().typeIndex()); } catch (Throwable ignored) {}
        try { o.addProperty("detail", iss.detail()); } catch (Throwable ignored) {}
        try { o.addProperty("remediation", iss.remediation()); } catch (Throwable ignored) {}
        return o;
    }
}
