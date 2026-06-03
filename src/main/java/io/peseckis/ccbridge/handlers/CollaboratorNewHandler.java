package io.peseckis.ccbridge.handlers;

import burp.api.montoya.collaborator.CollaboratorPayload;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;

import java.io.IOException;

public class CollaboratorNewHandler implements HttpHandler {

    private final CollaboratorRegistry registry;
    public CollaboratorNewHandler(CollaboratorRegistry registry) { this.registry = registry; }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }
        CollaboratorRegistry.Context ctx = registry.create();
        if (ctx == null) {
            java.util.Map<String, Object> err = new java.util.HashMap<>();
            err.put("error", "collaborator_unavailable");
            err.put("hint", "Burp Collaborator is Professional-only — not available in Burp Community.");
            ApiServer.Responses.json(ex, 501, err);
            return;
        }
        CollaboratorPayload payload = registry.addPayload(ctx);

        JsonObject out = new JsonObject();
        out.addProperty("context", ctx.id);
        out.addProperty("payload", payload.toString());
        out.addProperty("interactionId", payload.id().toString());
        out.addProperty("hint", "poll: GET /collaborator/" + ctx.id);
        ApiServer.Responses.json(ex, 200, out);
    }
}
