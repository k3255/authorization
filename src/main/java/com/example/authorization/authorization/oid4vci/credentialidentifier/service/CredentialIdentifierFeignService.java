package com.example.authorization.authorization.oid4vci.credentialidentifier.service;

import com.example.authorization.authorization.oid4vci.credentialidentifier.api.IssuerFeign;
import com.nimbusds.jose.shaded.gson.Gson;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialIdentifierFeignService {

    private final IssuerFeign issuerFeign;

    public List<String> getCredentialIdentifier(String credentialConfigurationId) {
        // refresh token 발급여부나 등록한 client 셋팅..
//        List<String> degreeList = Collections.singletonList("UniversityDegree");

        try {
            // todo: 우선 학생증 VC 기준으로,.,, 하드코딩
            List<String> response = issuerFeign.sendCredentialIdentifier(credentialConfigurationId);

            log.info("Successfully received response from issuer server.");
            log.info("credential_identifiers: {}", new Gson().toJson(response));

            return response;
        } catch (Exception e) {
            log.error("An error occurred while sending notification: {}", e.getMessage());
            throw new RuntimeException("Failed to get credential identifier from issuer", e);
        }
    }
}
