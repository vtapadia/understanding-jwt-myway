package com.github.vtapadia.example.jwt.service;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.UUID;

@Service
@Slf4j
public class KeyManagerEC implements KeyManager {
    private ECKey signKey, encryptKey;

    @PostConstruct
    public void init() throws Exception {
        signKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                .algorithm(JWSAlgorithm.ES256)
                .generate();

        encryptKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                .algorithm(JWEAlgorithm.ECDH_ES_A256KW)
                .generate();

    }

    public ECKey getSignKey() {
        return signKey;
    }

    public ECKey getEncryptKey() {
        return encryptKey;
    }

    public KeyType getKeyType() {
        return KeyType.EC;
    }
}
