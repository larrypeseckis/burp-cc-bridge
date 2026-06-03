package io.peseckis.ccbridge.handlers;

import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SmtpDetails;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CollaboratorPollHandler implements HttpHandler {

    private final CollaboratorRegistry registry;
    public CollaboratorPollHandler(CollaboratorRegistry registry) { this.registry = registry; }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if ("POST".equalsIgnoreCase(ex.getRequestMethod())) {
            // POST /collaborator/{ctx} -> mint another payload bound to this context
            String ctxId = tail(ex);
            CollaboratorRegistry.Context ctx = registry.get(ctxId);
            if (ctx == null) { notFound(ex, ctxId); return; }
            var p = registry.addPayload(ctx);
            JsonObject out = new JsonObject();
            out.addProperty("context", ctx.id);
            out.addProperty("payload", p.toString());
            out.addProperty("interactionId", p.id().toString());
            ApiServer.Responses.json(ex, 200, out);
            return;
        }
        if (!"GET".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }

        String ctxId = tail(ex);
        CollaboratorRegistry.Context ctx = registry.get(ctxId);
        if (ctx == null) { notFound(ex, ctxId); return; }

        List<Interaction> interactions = registry.poll(ctx);
        JsonArray arr = new JsonArray();
        for (Interaction it : interactions) {
            JsonObject o = new JsonObject();
            try { o.addProperty("type", it.type().name()); } catch (Throwable ignored) {}
            try { o.addProperty("interactionId", it.id().toString()); } catch (Throwable ignored) {}
            try { o.addProperty("clientIp", it.clientIp() == null ? null : it.clientIp().toString()); } catch (Throwable ignored) {}
            try { o.addProperty("timestamp", it.timeStamp().toString()); } catch (Throwable ignored) {}
            try {
                it.httpDetails().ifPresent(d -> {
                    HttpDetails h = d;
                    JsonObject http = new JsonObject();
                    try { http.addProperty("protocol", h.protocol().name()); } catch (Throwable ignored) {}
                    try { http.addProperty("requestRaw", h.requestResponse().request().toString()); } catch (Throwable ignored) {}
                    try { http.addProperty("responseRaw", h.requestResponse().response() != null ? h.requestResponse().response().toString() : null); } catch (Throwable ignored) {}
                    o.add("http", http);
                });
            } catch (Throwable ignored) {}
            try {
                it.dnsDetails().ifPresent(d -> {
                    DnsDetails dn = d;
                    JsonObject dns = new JsonObject();
                    try { dns.addProperty("queryType", dn.queryType().name()); } catch (Throwable ignored) {}
                    o.add("dns", dns);
                });
            } catch (Throwable ignored) {}
            try {
                it.smtpDetails().ifPresent(d -> {
                    SmtpDetails s = d;
                    JsonObject smtp = new JsonObject();
                    try { smtp.addProperty("conversation", s.conversation()); } catch (Throwable ignored) {}
                    try { smtp.addProperty("protocol", s.protocol().name()); } catch (Throwable ignored) {}
                    o.add("smtp", smtp);
                });
            } catch (Throwable ignored) {}
            arr.add(o);
        }
        JsonObject out = new JsonObject();
        out.addProperty("context", ctx.id);
        out.addProperty("count", arr.size());
        out.add("interactions", arr);
        ApiServer.Responses.json(ex, 200, out);
    }

    private String tail(HttpExchange ex) {
        return ex.getRequestURI().getPath().substring("/collaborator/".length());
    }

    private void notFound(HttpExchange ex, String ctxId) throws IOException {
        Map<String, Object> err = new HashMap<>();
        err.put("error", "not_found"); err.put("context", ctxId);
        ApiServer.Responses.json(ex, 404, err);
    }
}
