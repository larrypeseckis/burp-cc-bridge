package io.peseckis.ccbridge.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;
import io.peseckis.ccbridge.util.Json;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class RepeatHandler implements HttpHandler {

    private final MontoyaApi api;
    private final HistoryStore store;

    public RepeatHandler(MontoyaApi api, HistoryStore store) {
        this.api = api;
        this.store = store;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }

        String path = ex.getRequestURI().getPath();
        String tail = path.substring("/repeat/".length());
        long id;
        try { id = Long.parseLong(tail); } catch (NumberFormatException e) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "bad_id"); err.put("hint", "POST /repeat/{numericId}");
            ApiServer.Responses.json(ex, 400, err); return;
        }

        HistoryStore.Entry base = store.get(id);
        if (base == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "not_found"); err.put("id", id);
            ApiServer.Responses.json(ex, 404, err); return;
        }

        JsonObject body = Json.parseObject(ex.getRequestBody());
        HttpRequest req = base.rr().request();

        if (body.has("method") && !body.get("method").isJsonNull()) {
            req = req.withMethod(body.get("method").getAsString());
        }
        if (body.has("url") && !body.get("url").isJsonNull()) {
            // Re-base path/host on the new URL while preserving headers/body.
            HttpRequest fresh = HttpRequest.httpRequestFromUrl(body.get("url").getAsString());
            req = fresh.withMethod(req.method()).withBody(req.body());
            for (var h : base.rr().request().headers()) {
                // Skip auto-managed headers; let Burp recompute on send.
                String n = h.name().toLowerCase();
                if (n.equals("host") || n.equals("content-length")) continue;
                req = req.withHeader(h.name(), h.value());
            }
        }
        if (body.has("headers") && body.get("headers").isJsonObject()) {
            for (Map.Entry<String, JsonElement> h : body.getAsJsonObject("headers").entrySet()) {
                req = req.withHeader(h.getKey(), h.getValue().getAsString());
            }
        }
        if (body.has("removeHeaders") && body.get("removeHeaders").isJsonArray()) {
            for (var el : body.getAsJsonArray("removeHeaders")) {
                req = req.withRemovedHeader(el.getAsString());
            }
        }
        if (body.has("body") && !body.get("body").isJsonNull()) {
            req = req.withBody(body.get("body").getAsString());
        }

        HttpRequestResponse rr = api.http().sendRequest(req);
        HistoryStore.Entry stored = store.put(rr, Json.getString(body, "label", "repeat:" + id));
        ApiServer.Responses.json(ex, 200, SendHandler.RequestBuilder.summarize(stored, true));
    }
}
