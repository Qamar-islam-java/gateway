package com.crescent.hms.filter;


import com.crescent.hms.util.JwtUtil;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final JwtUtil jwtUtil;

    public AuthenticationFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 1. Check if the request contains the Authorization header
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Missing Authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

            // 2. Check if it starts with "Bearer "
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                // 3. Validate Token
                if (jwtUtil.validateToken(token)) {
                    String username = jwtUtil.extractUsername(token);

                    // 4. Add user details to headers for downstream services (Optional but useful)
                    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                            .header("X-User-Id", username)
                            .build();

                    return chain.filter(exchange.mutate().request(modifiedRequest).build());
                } else {
                    return onError(exchange, "Invalid Token", HttpStatus.UNAUTHORIZED);
                }
            }

            return onError(exchange, "Invalid Authorization format", HttpStatus.UNAUTHORIZED);
        };
    }

    // Helper method to return an error
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        org.springframework.http.server.reactive.ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().add("Content-Type", "application/json");

        String body = String.format("{\"status\": %d, \"error\": \"%s\"}", httpStatus.value(), err);
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    public static class Config {
        // Configuration properties if we need them later
    }
}
