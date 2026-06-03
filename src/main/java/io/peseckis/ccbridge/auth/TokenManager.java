package io.peseckis.ccbridge.auth;

import burp.api.montoya.logging.Logging;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;

public final class TokenManager {

    private TokenManager() {}

    public static String loadOrCreate(Logging log) throws Exception {
        Path tokenPath = Paths.get(System.getProperty("user.home"), ".cc-bridge-token");
        if (Files.isRegularFile(tokenPath)) {
            String existing = new String(Files.readAllBytes(tokenPath), StandardCharsets.UTF_8).trim();
            if (!existing.isEmpty()) {
                log.logToOutput("CC-Bridge: reusing existing token at " + tokenPath);
                return existing;
            }
        }

        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        Files.write(tokenPath, (token + "\n").getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        try {
            Files.setPosixFilePermissions(tokenPath, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX FS (e.g. Windows); skip chmod
        }
        log.logToOutput("CC-Bridge: new token written to " + tokenPath);
        return token;
    }

    public static boolean validate(String headerValue, String expected) {
        if (headerValue == null) return false;
        String prefix = "Bearer ";
        if (!headerValue.startsWith(prefix)) return false;
        String supplied = headerValue.substring(prefix.length()).trim();
        if (supplied.length() != expected.length()) return false;
        int diff = 0;
        for (int i = 0; i < supplied.length(); i++) diff |= supplied.charAt(i) ^ expected.charAt(i);
        return diff == 0;
    }
}
