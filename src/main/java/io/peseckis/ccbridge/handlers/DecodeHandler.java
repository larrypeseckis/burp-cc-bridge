package io.peseckis.ccbridge.handlers;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.peseckis.ccbridge.ApiServer;
import io.peseckis.ccbridge.util.Json;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;

public class DecodeHandler implements HttpHandler {

    private final MontoyaApi api;
    public DecodeHandler(MontoyaApi api) { this.api = api; }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) { ApiServer.Responses.methodNotAllowed(ex); return; }
        JsonObject body = Json.parseObject(ex.getRequestBody());
        String input = Json.getString(body, "input", null);
        String kind = Json.getString(body, "kind", "auto").toLowerCase();
        if (input == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "bad_request"); err.put("hint", "Body: {input, kind: auto|b64|b64url|url|hex|jwt|gzip}");
            ApiServer.Responses.json(ex, 400, err); return;
        }
        JsonObject out = new JsonObject();
        out.addProperty("kind", kind);
        try {
            switch (kind) {
                case "auto":  out.add("results", autoDecode(input)); break;
                case "b64":   out.addProperty("output", new String(Base64.getDecoder().decode(input), StandardCharsets.UTF_8)); break;
                case "b64url":out.addProperty("output", new String(Base64.getUrlDecoder().decode(input), StandardCharsets.UTF_8)); break;
                case "url":   out.addProperty("output", URLDecoder.decode(input, StandardCharsets.UTF_8)); break;
                case "hex":   out.addProperty("output", new String(hexDecode(input), StandardCharsets.UTF_8)); break;
                case "jwt":   out.add("output", jwtDecode(input)); break;
                case "gzip":  out.addProperty("output", new String(gunzip(Base64.getDecoder().decode(input)), StandardCharsets.UTF_8)); break;
                default:      throw new IllegalArgumentException("unknown kind: " + kind);
            }
            ApiServer.Responses.json(ex, 200, out);
        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "decode_failed"); err.put("kind", kind); err.put("message", e.getMessage());
            ApiServer.Responses.json(ex, 400, err);
        }
    }

    private JsonArray autoDecode(String input) {
        JsonArray arr = new JsonArray();
        // JWT
        if (input.matches("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$")) {
            try { JsonObject o = new JsonObject(); o.addProperty("kind", "jwt"); o.add("value", jwtDecode(input)); arr.add(o); } catch (Exception ignored) {}
        }
        // URL-encoded
        if (input.contains("%")) {
            try {
                String d = URLDecoder.decode(input, StandardCharsets.UTF_8);
                if (!d.equals(input)) { JsonObject o = new JsonObject(); o.addProperty("kind", "url"); o.addProperty("value", d); arr.add(o); }
            } catch (Exception ignored) {}
        }
        // Base64
        try {
            byte[] raw = Base64.getDecoder().decode(input);
            String s = new String(raw, StandardCharsets.UTF_8);
            if (looksPrintable(s)) { JsonObject o = new JsonObject(); o.addProperty("kind", "b64"); o.addProperty("value", s); arr.add(o); }
        } catch (Exception ignored) {}
        // Base64URL
        try {
            byte[] raw = Base64.getUrlDecoder().decode(input);
            String s = new String(raw, StandardCharsets.UTF_8);
            if (looksPrintable(s)) { JsonObject o = new JsonObject(); o.addProperty("kind", "b64url"); o.addProperty("value", s); arr.add(o); }
        } catch (Exception ignored) {}
        // Hex
        if (input.matches("^[0-9a-fA-F]+$") && input.length() % 2 == 0) {
            try { String s = new String(hexDecode(input), StandardCharsets.UTF_8); if (looksPrintable(s)) { JsonObject o = new JsonObject(); o.addProperty("kind", "hex"); o.addProperty("value", s); arr.add(o); } } catch (Exception ignored) {}
        }
        return arr;
    }

    private static boolean looksPrintable(String s) {
        if (s.isEmpty()) return false;
        int printable = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t') printable++;
        }
        return ((double) printable / s.length()) > 0.85;
    }

    private static byte[] hexDecode(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static byte[] gunzip(byte[] gz) throws IOException {
        try (var in = new GZIPInputStream(new ByteArrayInputStream(gz))) { return in.readAllBytes(); }
    }

    private static JsonObject jwtDecode(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("not a JWT");
        JsonObject o = new JsonObject();
        o.add("header",    JsonParser.parseString(new String(Base64.getUrlDecoder().decode(pad(parts[0])), StandardCharsets.UTF_8)));
        o.add("payload",   JsonParser.parseString(new String(Base64.getUrlDecoder().decode(pad(parts[1])), StandardCharsets.UTF_8)));
        o.addProperty("signature", parts.length >= 3 ? parts[2] : "");
        return o;
    }
    private static String pad(String s) { return s + "===".substring((s.length() % 4 == 0) ? 3 : (s.length() % 4) - 1); }
}
