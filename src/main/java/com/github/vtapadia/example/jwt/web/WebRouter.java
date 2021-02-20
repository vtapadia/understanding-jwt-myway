package com.github.vtapadia.example.jwt.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

@Configuration
public class WebRouter {
    @Bean
    public RouterFunction<ServerResponse> route(JWKHandler jwkHandler, JWEMessageHander jweMessageHander) {

        return RouterFunctions
                .route(RequestPredicates.GET("/jwk").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)), jwkHandler::jwks)
                .andRoute(RequestPredicates.GET("/secure/send"), jweMessageHander::sender);
    }
}
