package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RsaKeyProperties rsaKeys;

    public SecurityConfig(RsaKeyProperties rsaKeys) {
        this.rsaKeys = rsaKeys;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(rsaKeys.publicKey()).privateKey(rsaKeys.privateKey()).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));

        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/register").anonymous()
                        .requestMatchers("/token/refresh").access((authenticationSupplier, context) -> {
                            System.out.println("this is from any refresh url");
                            Authentication authentication = authenticationSupplier.get();
                            if (authentication == null || !authentication.isAuthenticated()
                                    || authentication instanceof AnonymousAuthenticationToken) {
                                return new AuthorizationDecision(false);
                            }

                            if (authentication instanceof JwtAuthenticationToken jwtAuth) {
                                String type = jwtAuth.getToken().getClaimAsString("type");
                                boolean allowed = "refresh".equals(type);
                                return new AuthorizationDecision(allowed);
                            }
                            return new AuthorizationDecision(false);
                        })
                        .anyRequest().access((authenticationSupplier, context) -> {
                            System.out.println("this is from any request");
                            Authentication authentication = authenticationSupplier.get();
                            if (authentication == null || !authentication.isAuthenticated()
                                    || authentication instanceof AnonymousAuthenticationToken) {
                                return new AuthorizationDecision(false);
                            }

                            if (authentication instanceof JwtAuthenticationToken jwtAuth) {
                                String type = jwtAuth.getToken().getClaimAsString("type");
                                boolean allowed = "access".equals(type);
                                return new AuthorizationDecision(allowed);
                            }

                            return new AuthorizationDecision(false);
                        }))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder())))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }
}
