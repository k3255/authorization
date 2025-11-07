package com.example.authorization.authorization.repository;

import com.example.authorization.authorization.oid4vci.preauthorized.dto.PreAuthorizedCode;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class InMemoryPreAuthorizedCodeRepository {

    private final ConcurrentHashMap<String, PreAuthorizedCode> codes = new ConcurrentHashMap<>();

    public void save(PreAuthorizedCode preAuthorizedCode) {
        codes.put(preAuthorizedCode.getValue(), preAuthorizedCode);
    }

    public Optional<PreAuthorizedCode> findByValue(String code) {
        PreAuthorizedCode preAuthorizedCode = codes.get(code);
        if (preAuthorizedCode != null && preAuthorizedCode.isExpired()) {
            codes.remove(code);
            return Optional.empty();
        }
        return Optional.ofNullable(preAuthorizedCode);
    }

    public Optional<PreAuthorizedCode> remove(String code) {
        return Optional.ofNullable(codes.remove(code));
    }
}
