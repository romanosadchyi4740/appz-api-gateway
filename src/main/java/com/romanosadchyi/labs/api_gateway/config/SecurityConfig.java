package com.romanosadchyi.labs.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                // Disable CSRF (Cross-Site Request Forgery) as we are stateless
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // Enable CORS - configuration is handled by CorsConfig
                // Allow ALL requests to pass through the security filter chain
                // This is safe because your 'AuthenticationFilter' handles the actual security logic
                .authorizeExchange(exchange -> exchange
                        .anyExchange().permitAll()
                )
                .build();
    }
}
