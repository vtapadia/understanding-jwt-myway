package com.github.vtapadia.example.jwt.web;

import com.github.vtapadia.example.jwt.domain.EncryptedData;
import com.github.vtapadia.example.jwt.service.KeyManager;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.util.Date;
import java.util.List;

@Component
public class JWEMessageHander {
    @Qualifier("keyManagerRSA")
    @Autowired
    private KeyManager keyManager;

    public Mono<ServerResponse> sender(ServerRequest request) {
        //Get the signing Key
        JWK signKey = keyManager.getSignKey();

        //Build the payload
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("subject")
                .issuer("varesh")
                .issueTime(new Date())
                .claim("data", "my secure payload")
                .build();

        //Create the JWT Object
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.parse(signKey.getAlgorithm().getName())) // RS256 or ES256
                        .keyID(signKey.getKeyID())
                        .contentType("application/vnd.example.secure-message.v1+json")
                        .build(),
                claimsSet);

        // Compute the RSA signature using private key
        try {
            if (signKey.getKeyType() == KeyType.RSA) {
                signedJWT.sign(new RSASSASigner(signKey.toRSAKey()));
            } else if (signKey.getKeyType() == KeyType.EC) {
                signedJWT.sign(new ECDSASigner(signKey.toECKey()));
            } else {
                throw new RuntimeException("Unsupported Key found");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        //Retrieve the Encryption key
        JWKSet jwkSet;
        try {
            URL url = new URL("http://localhost:8080/jwk");
            jwkSet = JWKSet.load(url);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        JWKMatcher encryptKeyMatcher = new JWKMatcher.Builder().keyUse(KeyUse.ENCRYPTION).keyType(keyManager.getKeyType()).build();
        JWKSelector jwkSelector = new JWKSelector(encryptKeyMatcher);
        List<JWK> keyList = jwkSelector.select(jwkSet);
        JWK jwkEncryption = keyList.get(0);

        //Create the JWE payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.parse(jwkEncryption.getAlgorithm().getName()), EncryptionMethod.A256GCM)
                        .contentType("JWT") // required to indicate nested JWT
                        .keyID(jwkEncryption.getKeyID())
                        .build(),
                new Payload(signedJWT));

        // Encrypt with the recipient's public key
        try {
            if (jwkEncryption.getKeyType() == KeyType.RSA) {
                jweObject.encrypt(new RSAEncrypter(jwkEncryption.toRSAKey()));
            } else if (jwkEncryption.getKeyType() == KeyType.EC){
                jweObject.encrypt(new ECDHEncrypter(jwkEncryption.toECKey()));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        EncryptedData encryptedData = new EncryptedData(jweObject.serialize());

        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(encryptedData));
    }

    public Mono<ServerResponse> receiver(ServerRequest request) {
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(""));
    }

}
