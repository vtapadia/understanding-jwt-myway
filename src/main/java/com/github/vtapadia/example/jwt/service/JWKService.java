package com.github.vtapadia.example.jwt.service;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class JWKService {
    private WebClient client = WebClient.create("http://localhost:8080");


    public Mono<JWKSet> load() {
        return client.get().uri("/jwk").retrieve().bodyToMono(JWKSet.class);
    }
}
