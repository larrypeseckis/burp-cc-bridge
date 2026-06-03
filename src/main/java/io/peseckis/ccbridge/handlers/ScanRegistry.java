package io.peseckis.ccbridge.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.Audit;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class ScanRegistry {

    public record Task(long id, long createdAtMillis, String label, Audit audit) {}

    private final MontoyaApi api;
    private final AtomicLong counter = new AtomicLong(1);
    private final Map<Long, Task> tasks = new ConcurrentHashMap<>();

    public ScanRegistry(MontoyaApi api) { this.api = api; }

    public Task register(Audit audit, String label) {
        long id = counter.getAndIncrement();
        Task t = new Task(id, System.currentTimeMillis(), label, audit);
        tasks.put(id, t);
        return t;
    }

    public Task get(long id) { return tasks.get(id); }

    public java.util.Collection<Task> all() { return tasks.values(); }

    public void cancel(long id) {
        Task t = tasks.remove(id);
        if (t != null) try { t.audit.delete(); } catch (Throwable ignored) {}
    }
}
