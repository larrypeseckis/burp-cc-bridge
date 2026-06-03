package io.peseckis.ccbridge.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;
import io.peseckis.ccbridge.util.Json;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class SendHandler implements HttpHandler {

    private final MontoyaApi api;
    private final HistoryStore store;

    public SendHandler(MontoyaApi api, HistoryStore store) {
        this.api = api;
        this.store = store;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }

        JsonObject body = Json.parseObject(ex.getRequestBody());
        HttpRequest req = RequestBuilder.fromJson(body);
        if (req == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "bad_request");
            err.put("hint", "Provide either {raw, host, port?, tls?} or {method, url, headers?, body?}");
            ApiServer.Responses.json(ex, 400, err);
            return;
        }

        HttpRequestResponse rr = api.http().sendRequest(req);
        HistoryStore.Entry stored = store.put(rr, Json.getString(body, "label", "send"));

        ApiServer.Responses.json(ex, 200, RequestBuilder.summarize(stored, true));
    }

    /** Shared helpers for building/serializing HttpRequest objects. */
    public static final class RequestBuilder {

        public static HttpRequest fromJson(JsonObject body) {
            // Path 1: raw text request + service descriptor.
            String raw = Json.getString(body, "raw", null);
            if (raw != null && !raw.isBlank()) {
                String host = Json.getString(body, "host", null);
                int port   = Json.getInt(body, "port", -1);
                boolean tls = Json.getBool(body, "tls", port == 443);
                if (host == null || port <= 0) return null;
                HttpService svc = HttpService.httpService(host, port, tls);
                return HttpRequest.httpRequest(svc, ByteArray.byteArray(raw.replace("\n", "\r\n")));
            }

            // Path 2: structured {method, url, headers, body}.
            String url = Json.getString(body, "url", null);
            if (url == null) return null;

            HttpRequest req = HttpRequest.httpRequestFromUrl(url);
            String method = Json.getString(body, "method", "GET");
            req = req.withMethod(method);

            if (body.has("headers") && body.get("headers").isJsonObject()) {
                JsonObject headers = body.getAsJsonObject("headers");
                for (Map.Entry<String, JsonElement> h : headers.entrySet()) {
                    req = req.withHeader(h.getKey(), h.getValue().getAsString());
                }
            }
            if (body.has("body") && !body.get("body").isJsonNull()) {
                String payload = body.get("body").getAsString();
                req = req.withBody(payload);
            }
            return req;
        }

        public static JsonObject summarize(HistoryStore.Entry entry, boolean includeBodies) {
            HttpRequestResponse rr = entry.rr();
            HttpRequest req = rr.request();
            HttpResponse res = rr.response();
            JsonObject o = new JsonObject();
            o.addProperty("id", entry.id());
            o.addProperty("sentAt", entry.sentAtMillis());
            o.addProperty("label", entry.label());

            JsonObject reqJson = new JsonObject();
            reqJson.addProperty("method", req.method());
            reqJson.addProperty("url", safeUrl(req));
            reqJson.addProperty("path", req.path());
            reqJson.addProperty("host", req.httpService() != null ? req.httpService().host() : null);
            reqJson.addProperty("port", req.httpService() != null ? req.httpService().port() : 0);
            reqJson.addProperty("tls", req.httpService() != null && req.httpService().secure());
            reqJson.add("headers", headersToJson(req.headers()));
            if (includeBodies) {
                reqJson.addProperty("body", req.bodyToString());
                reqJson.addProperty("length", req.body().length());
            }
            o.add("request", reqJson);

            if (res != null) {
                JsonObject resJson = new JsonObject();
                resJson.addProperty("status", res.statusCode());
                resJson.addProperty("reason", res.reasonPhrase());
                resJson.addProperty("mime", res.mimeType().name());
                resJson.add("headers", headersToJson(res.headers()));
                if (includeBodies) {
                    resJson.addProperty("body", res.bodyToString());
                    resJson.addProperty("length", res.body().length());
                }
                o.add("response", resJson);
            }
            return o;
        }

        private static String safeUrl(HttpRequest req) {
            try { return req.url(); } catch (Throwable t) {
                if (req.httpService() == null) return req.path();
                return (req.httpService().secure() ? "https://" : "http://")
                        + req.httpService().host()
                        + ((req.httpService().port() == 80 || req.httpService().port() == 443) ? "" : ":" + req.httpService().port())
                        + req.path();
            }
        }

        private static JsonArray headersToJson(java.util.List<burp.api.montoya.http.message.HttpHeader> headers) {
            JsonArray arr = new JsonArray();
            for (var h : headers) {
                JsonArray pair = new JsonArray();
                pair.add(h.name());
                pair.add(h.value());
                arr.add(pair);
            }
            return arr;
        }
    }
}
