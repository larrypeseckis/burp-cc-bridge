package io.peseckis.ccbridge.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class Json {

    public static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    public static final Gson PRETTY = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    private Json() {}

    public static JsonObject parseObject(InputStream in) throws IOException {
        String raw = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        if (raw.isBlank()) return new JsonObject();
        JsonElement el = JsonParser.parseString(raw);
        if (!el.isJsonObject()) throw new IOException("body is not a JSON object");
        return el.getAsJsonObject();
    }

    public static String getString(JsonObject o, String key, String dflt) {
        return (o.has(key) && !o.get(key).isJsonNull()) ? o.get(key).getAsString() : dflt;
    }

    public static int getInt(JsonObject o, String key, int dflt) {
        return (o.has(key) && !o.get(key).isJsonNull()) ? o.get(key).getAsInt() : dflt;
    }

    public static boolean getBool(JsonObject o, String key, boolean dflt) {
        return (o.has(key) && !o.get(key).isJsonNull()) ? o.get(key).getAsBoolean() : dflt;
    }
}
