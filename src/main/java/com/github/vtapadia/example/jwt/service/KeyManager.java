package com.github.vtapadia.example.jwt.service;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;

public interface KeyManager {
    JWK getSignKey();

    JWK getEncryptKey();

    KeyType getKeyType();
}
