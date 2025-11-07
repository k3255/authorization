package com.example.authorization.authorization.oid4vci.preauthorized.dto;

public class PreAuthorizedCodeResponse {

    private final String preAuthorizedCode;
    private final int expiresIn;
    private final String userPin;


    public PreAuthorizedCodeResponse(String preAuthorizedCode, int expiresIn, String userPin) {
        this.preAuthorizedCode = preAuthorizedCode;
        this.expiresIn = expiresIn;
        this.userPin = userPin;
    }

    public String getPreAuthorizedCode() {
        return preAuthorizedCode;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public String getUserPin() {
        return userPin;
    }
}
