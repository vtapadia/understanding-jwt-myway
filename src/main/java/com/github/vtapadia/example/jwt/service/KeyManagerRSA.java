package com.github.vtapadia.example.jwt.service;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Component
@Slf4j
public class KeyManagerRSA implements KeyManager {
    private RSAKey signKey, encryptKey;
    private KeyPair signKeyPair;

    @PostConstruct
    public void init() throws Exception {
        //Generating RSA key using Key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        signKeyPair = gen.generateKeyPair();

        signKey = new RSAKey.Builder((RSAPublicKey) signKeyPair.getPublic())
                .privateKey((RSAPrivateKey) signKeyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(UUID.randomUUID().toString())
                .build();

        //Generating RSA Key using RSA Key Generator
        encryptKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                .algorithm(JWEAlgorithm.RSA_OAEP_256)
                .generate();
    }


    public RSAKey getSignKey() {
        return signKey;
    }
    public RSAKey getEncryptKey() {
        return encryptKey;
    }
    public KeyType getKeyType() {
        return KeyType.RSA;
    }


    public void printKeyInPEM(RSAKey rsaKey) throws Exception {
        PemObject rsa_public_key = new PemObject("RSA Public Key", rsaKey.toPublicKey().getEncoded());
        StringWriter stw = new StringWriter();
        PemWriter pw = new PemWriter(stw);
        pw.writeObject(rsa_public_key.generate());
        pw.close();
        stw.close();
        log.debug("Pem format for keyId {} \n{}", rsaKey.getKeyID(), stw.toString());
    }

}
