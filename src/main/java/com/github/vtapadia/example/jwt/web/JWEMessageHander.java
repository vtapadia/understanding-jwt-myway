package com.github.vtapadia.example.jwt.web;

import com.github.vtapadia.example.jwt.domain.EncryptedData;
import com.github.vtapadia.example.jwt.service.KeyManager;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Component showing both the sending and receiving logic for Signing and encryption of a message in JWT formats
 * Also uses JWK to display the benefits of using keys exposed for this purpose
 */
@Component
@Slf4j
public class JWEMessageHander {
    @Qualifier("keyManagerRSA")
    @Autowired
    private KeyManager keyManager;

    private WebClient client = WebClient.create("http://localhost:8080");

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

        client.post().uri("/secure/receive").body(BodyInserters.fromValue(encryptedData)).exchangeToMono(response -> {
            if (response.statusCode().is2xxSuccessful()) {
                log.info("Success call made to receiver");
            }
            return response.bodyToMono(Map.class);
        });

        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(encryptedData));
    }

    public Mono<ServerResponse> receiver(ServerRequest request) {
        EncryptedData encryptedData = request.bodyToMono(EncryptedData.class).block();

        JWK encryptKey = keyManager.getEncryptKey();

        EncryptedJWT encryptedJWT = null;
        try {
            encryptedJWT = EncryptedJWT.parse(encryptedData.getEncrypted());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        log.info("Headers::{}", encryptedJWT.getHeader());

        //Here one can check and retrieve the corresponding Decryption key for the payload.
        Assert.isTrue(encryptedJWT.getHeader().getKeyID().equalsIgnoreCase(encryptKey.getKeyID()),
                "Invalid key used for encryption");
        //One can also ensure that the Encryption algorithms are those that are supported.
        Assert.isTrue(Arrays.asList(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.ECDH_ES_A256KW).contains(encryptedJWT.getHeader().getAlgorithm()),
                "Unsupported algorithm used for encryption");

        //Decrypt the JWE Object
        try {
            if (encryptKey.getKeyType() == KeyType.RSA) {
                encryptedJWT.decrypt(new RSADecrypter(encryptKey.toRSAKey().toPrivateKey()));
            } else if (encryptKey.getKeyType() == KeyType.EC) {
                encryptedJWT.decrypt(new ECDHDecrypter(encryptKey.toECKey().toECPrivateKey()));
            }
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        log.info("Get payload type :: {}", encryptedJWT.getPayload().getClass());

        //Gets the payload as a Signed JWT
        SignedJWT signedJWT = encryptedJWT.getPayload().toSignedJWT();
        log.info("Signed header :: {}", signedJWT.getHeader());

        //Retrieve the Signing verification key
        JWKSet jwkSet;
        try {
            URL url = new URL("http://localhost:8080/jwk");
            jwkSet = JWKSet.load(url);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        //Select the matching public key from the JWK endpoint.
        JWKMatcher encryptKeyMatcher = new JWKMatcher.Builder()
                .keyUse(KeyUse.SIGNATURE)
                .keyID(signedJWT.getHeader().getKeyID())
                .build();
        JWKSelector jwkSelector = new JWKSelector(encryptKeyMatcher);
        List<JWK> keyList = jwkSelector.select(jwkSet);
        JWK jwkSigning = keyList.get(0);

        //Signature verification
        try {
            if (jwkSigning.getKeyType() == KeyType.RSA) {
                Assert.isTrue(signedJWT.verify(new RSASSAVerifier(jwkSigning.toRSAKey())),
                        "Signature verification failed");
            } else if (jwkSigning.getKeyType() == KeyType.EC) {
                Assert.isTrue(signedJWT.verify(new ECDSAVerifier(jwkSigning.toECKey())),
                        "Signature verification failed");
            } else {
                throw new RuntimeException("Unknown key type for signing");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        //Logs the signed and encrypted payload
        log.info("Message body received:: \n{}", signedJWT.getPayload());

        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }

}
