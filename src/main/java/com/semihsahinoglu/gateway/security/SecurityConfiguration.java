package com.semihsahinoglu.gateway.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity) {

        httpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange->exchange.pathMatchers("/api/v1/auth/**").permitAll())
                .authorizeExchange(exchange->exchange.pathMatchers("/actuator/**").permitAll())
                .authorizeExchange(exchange->exchange.anyExchange().authenticated());

        return httpSecurity.build();
    }
}
