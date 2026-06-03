package io.peseckis.ccbridge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import io.peseckis.ccbridge.auth.TokenManager;

public class CCBridgeExtension implements BurpExtension {

    private ApiServer server;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("CC-Bridge");
        Logging log = api.logging();

        String host = System.getProperty("ccbridge.host", "127.0.0.1");
        int port = Integer.getInteger("ccbridge.port", 1337);

        try {
            String token = TokenManager.loadOrCreate(log);
            server = new ApiServer(api, host, port, token);
            server.start();
            log.logToOutput("CC-Bridge listening on http://" + host + ":" + port);
            log.logToOutput("Auth token written to ~/.cc-bridge-token (mode 600)");
            log.logToOutput("Quick test:  curl -sH \"Authorization: Bearer $(cat ~/.cc-bridge-token)\" http://" + host + ":" + port + "/health");
        } catch (Exception e) {
            log.logToError("CC-Bridge failed to start: " + e.getMessage());
            e.printStackTrace();
        }

        api.extension().registerUnloadingHandler(() -> {
            if (server != null) server.stop();
            log.logToOutput("CC-Bridge stopped");
        });
    }
}
