package com.example.authorization.authorization.oid4vci.preauthorized.grant;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

public class PreAuthorizedCodeGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    public static final AuthorizationGrantType PRE_AUTHORIZED_CODE = new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code");

    private final String preAuthorizedCode;
    private final String txCode;

    public PreAuthorizedCodeGrantAuthenticationToken(Authentication clientPrincipal, String preAuthorizedCode, @Nullable String txCode, @Nullable Map<String, Object> additionalParameters) {
        super(PRE_AUTHORIZED_CODE, clientPrincipal, additionalParameters);
        this.preAuthorizedCode = preAuthorizedCode;
        this.txCode = txCode;
    }

    public String getPreAuthorizedCode() {
        return this.preAuthorizedCode;
    }

    @Nullable
    public String getTxCode() {
        return this.txCode;
    }
}
