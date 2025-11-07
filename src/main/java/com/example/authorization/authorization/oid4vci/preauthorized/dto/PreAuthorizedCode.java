package com.example.authorization.authorization.oid4vci.preauthorized.dto;

import java.time.Instant;
import java.util.Set;

public class PreAuthorizedCode {

    private final String value;
    private final Instant expiresAt;
    private final Set<String> scopes;
    private final String userPin;
    private final String cNonce;
    private boolean consumed;

    public PreAuthorizedCode(String value, Instant expiresAt, Set<String> scopes, String userPin, String cNonce) {
        this.value = value;
        this.expiresAt = expiresAt;
        this.scopes = scopes;
        this.userPin = userPin;
        this.cNonce = cNonce;
        this.consumed = false;
    }

    public String getValue() {
        return value;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public String getUserPin() {
        return userPin;
    }

    public String getCNonce() {
        return cNonce;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isConsumed() {
        return consumed;
    }

    public void setConsumed(boolean consumed) {
        this.consumed = consumed;
    }
}