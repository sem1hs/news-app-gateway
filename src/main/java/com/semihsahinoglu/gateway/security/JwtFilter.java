package com.semihsahinoglu.gateway.security;

import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;


@Component
public class JwtFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);
    private final JwtService jwtService;

    public JwtFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();
        log.info("Gateway request path: {}", path);

        if (path.startsWith("/api/v1/auth")) {
            log.info("Auth'a gönderiliyor, token kontrolü atlandı ");
            return chain.filter(exchange);
        }

        ServerHttpRequest request = exchange.getRequest();
        String header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        String token = null;

        if (header != null && header.startsWith("Bearer")) {
            log.info("Request Header  {}", header);
            token = header.substring(7);
            log.info("Request Token {}", token);
        }

        if (jwtService.validateToken(token)) {
            log.info("Token Doğrulandı {}", token);
        }
        return chain.filter(exchange);
    }
}
