package io.peseckis.ccbridge.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class CollaboratorRegistry {

    public static class Context {
        public final String id;
        public final long createdAtMillis;
        public final CollaboratorClient client;
        public final Map<String, CollaboratorPayload> payloads = new HashMap<>();

        Context(String id, CollaboratorClient client) {
            this.id = id; this.client = client; this.createdAtMillis = System.currentTimeMillis();
        }
    }

    private final MontoyaApi api;
    private final AtomicLong counter = new AtomicLong(1);
    private final Map<String, Context> contexts = new ConcurrentHashMap<>();

    public CollaboratorRegistry(MontoyaApi api) { this.api = api; }

    public Context create() {
        CollaboratorClient client;
        try { client = api.collaborator().createClient(); } catch (Throwable t) { client = null; }
        if (client == null) return null;
        String id = "c" + counter.getAndIncrement();
        Context ctx = new Context(id, client);
        contexts.put(id, ctx);
        return ctx;
    }

    public Context get(String id) { return contexts.get(id); }

    public CollaboratorPayload addPayload(Context ctx) {
        CollaboratorPayload p = ctx.client.generatePayload();
        ctx.payloads.put(p.id().toString(), p);
        return p;
    }

    public List<Interaction> poll(Context ctx) {
        return ctx.client.getAllInteractions();
    }
}
