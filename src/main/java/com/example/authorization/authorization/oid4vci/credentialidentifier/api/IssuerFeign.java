package com.example.authorization.authorization.oid4vci.credentialidentifier.api;


import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Map;

@FeignClient(name = "credential-issuer", url = "${clients.issuer-server.url}")
public interface IssuerFeign {

    @GetMapping("/get-credential-identifier")
    List<String> sendCredentialIdentifier(@RequestParam("credentialConfigurationId") String credentialConfigurationId);

}