package io.peseckis.ccbridge.handlers;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class HistoryItemHandler implements HttpHandler {

    private final MontoyaApi api;
    private final HistoryStore store;

    public HistoryItemHandler(MontoyaApi api, HistoryStore store) {
        this.api = api;
        this.store = store;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }

        String path = ex.getRequestURI().getPath();
        String tail = path.substring("/history/".length());
        long id;
        try { id = Long.parseLong(tail); } catch (NumberFormatException e) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "bad_id"); err.put("hint", "GET /history/{numericId}");
            ApiServer.Responses.json(ex, 400, err); return;
        }

        HistoryStore.Entry entry = store.get(id);
        if (entry == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "not_found"); err.put("id", id);
            ApiServer.Responses.json(ex, 404, err); return;
        }
        JsonObject body = SendHandler.RequestBuilder.summarize(entry, true);
        ApiServer.Responses.json(ex, 200, body);
    }
}
