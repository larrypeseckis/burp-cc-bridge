package io.peseckis.ccbridge.handlers;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tracks requests that originated via /send and /repeat so they can be referenced by a short numeric ID
 * even when Burp's own history index isn't convenient (e.g. cross-process).
 *
 * Bounded by MAX entries (LRU eviction); IDs are monotonic and never reused.
 */
public class HistoryStore {

    public record Entry(long id, long sentAtMillis, HttpRequestResponse rr, String label) {}

    private static final int MAX = 500;
    private final AtomicLong counter = new AtomicLong(1);
    private final Map<Long, Entry> entries = Collections.synchronizedMap(new LinkedHashMap<>() {
        @Override protected boolean removeEldestEntry(Map.Entry<Long, Entry> eldest) { return size() > MAX; }
    });

    public Entry put(HttpRequestResponse rr, String label) {
        long id = counter.getAndIncrement();
        Entry e = new Entry(id, System.currentTimeMillis(), rr, label);
        entries.put(id, e);
        return e;
    }

    public Entry get(long id) { return entries.get(id); }

    public java.util.List<Entry> snapshot() {
        synchronized (entries) {
            return new java.util.ArrayList<>(entries.values());
        }
    }
}
