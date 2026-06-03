package io.peseckis.ccbridge.handlers;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class HealthHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange ex) throws IOException {
        Map<String, Object> body = new HashMap<>();
        body.put("status", "ok");
        body.put("time", Instant.now().toString());
        ApiServer.Responses.json(ex, 200, body);
    }
}
