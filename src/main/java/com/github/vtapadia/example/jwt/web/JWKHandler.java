package com.github.vtapadia.example.jwt.web;

import com.github.vtapadia.example.jwt.service.KeyManager;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

@Component
public class JWKHandler {

    @Autowired
    private List<KeyManager> keyManagers;

    public Mono<ServerResponse> jwks(ServerRequest request) {
        List<JWK> keys = new ArrayList<>();
        keyManagers.forEach(k -> {
            keys.add(k.getSignKey());
            keys.add(k.getEncryptKey());
        });
        JWKSet jwkSet = new JWKSet(keys);
        CacheControl cc = CacheControl.maxAge(Duration.of(6, ChronoUnit.HOURS)).mustRevalidate();
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).cacheControl(cc)
                .body(BodyInserters.fromValue(jwkSet.toJSONObject(true)));
    }

}
