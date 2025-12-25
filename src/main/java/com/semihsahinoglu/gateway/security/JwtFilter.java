package com.semihsahinoglu.gateway.security;

import com.semihsahinoglu.gateway.exception.ErrorUtil;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;

import java.util.List;


@Component
public class JwtFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);
    private final JwtService jwtService;
    private final ErrorUtil errorUtil;

    public JwtFilter(JwtService jwtService, ErrorUtil errorUtil) {
        this.jwtService = jwtService;
        this.errorUtil = errorUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();
        String method = exchange.getRequest().getMethod().name();

        if (path.startsWith("/api/v1/auth")) {
            log.info("Auth'a gönderiliyor, token kontrolü atlandı ");
            return chain.filter(exchange);
        }

        if ("GET".equals(method) && path.startsWith("/api/v1/news")) {
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

        if (token == null) {
            return errorUtil.buildError(exchange, HttpStatus.UNAUTHORIZED, "Token gerekli !");
        }

        if (jwtService.validateToken(token)) {
            log.info("Token Doğrulandı {}", token);
            String username = jwtService.extractUsername(token);
            log.info("User Doğrulandı {}", username);
            List<GrantedAuthority> roles = jwtService.extractRoles(token);
            Authentication auth = new UsernamePasswordAuthenticationToken(username, null, roles);

            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
        }
        return chain.filter(exchange);
    }
}
