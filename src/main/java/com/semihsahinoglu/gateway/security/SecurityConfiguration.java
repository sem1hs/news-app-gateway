package com.semihsahinoglu.gateway.security;


import com.semihsahinoglu.gateway.exception.ErrorUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {

    private final JwtFilter filter;
    private final ErrorUtil errorUtil;

    public SecurityConfiguration(JwtFilter filter, ErrorUtil errorUtil) {
        this.filter = filter;
        this.errorUtil = errorUtil;
    }

    private ServerAuthenticationEntryPoint authEntryPoint() {
        return (exchange, e) ->
                errorUtil.buildError(exchange, HttpStatus.UNAUTHORIZED, "Token gerekli");
    }

    private ServerAccessDeniedHandler deniedHandler() {
        return (exchange, e) ->
                errorUtil.buildError(exchange, HttpStatus.FORBIDDEN, "Yetkiniz yok");
    }


    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity) {
        httpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authEntryPoint()))
                .exceptionHandling(exception -> exception.accessDeniedHandler(deniedHandler()))
                .authorizeExchange(exchange -> exchange.pathMatchers("/api/v1/auth/**").permitAll())
                .authorizeExchange(exchange -> exchange.pathMatchers(HttpMethod.GET,"/api/v1/news/**").permitAll())
                .authorizeExchange(exchange -> exchange.pathMatchers(HttpMethod.GET,"/api/v1/teams/**").permitAll())
                .authorizeExchange(exchange -> exchange.pathMatchers(HttpMethod.GET,"/api/v1/league/**").permitAll())
                .authorizeExchange(exchange -> exchange.pathMatchers(HttpMethod.GET,"/api/v1/fixture/**").permitAll())
                .authorizeExchange(exchange -> exchange.pathMatchers(HttpMethod.GET,"/api/v1/standing/**").permitAll())
                .authorizeExchange(exchange -> exchange.pathMatchers("/actuator/**").permitAll())
                .authorizeExchange(exchange -> exchange.anyExchange().authenticated())
                .addFilterBefore(filter, SecurityWebFiltersOrder.AUTHENTICATION);

        return httpSecurity.build();
    }

}
