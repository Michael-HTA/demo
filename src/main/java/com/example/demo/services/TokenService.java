package com.example.demo.services;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.example.demo.model.User;

@Service
public class TokenService {
    private final JwtEncoder encoder;

    public TokenService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

    public String generateToken(Authentication authentication, String tokenType, long amount, ChronoUnit unit) {
        String email = ((User) authentication.getPrincipal()).email();
        Long id = ((User) authentication.getPrincipal()).id();
        Instant now = Instant.now();
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(amount, unit))   // flexible expiry
                .subject(email)
                .claim("scope", scope)
                .claim("type", tokenType)            // distinguish access vs refresh
                .claim("id", id)
                .build();

        return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String generateAccessToken(Authentication authentication) {
        return generateToken(authentication, "access", 15, ChronoUnit.MINUTES);
    }

    public String generateRefreshToken(Authentication authentication) {
        return generateToken(authentication, "refresh", 7, ChronoUnit.DAYS);
    }
}

