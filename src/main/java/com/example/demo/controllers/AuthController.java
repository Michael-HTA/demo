package com.example.demo.controllers;

import org.springframework.web.bind.annotation.RestController;

import com.example.demo.repositories.RefreshTokenRepository;
import com.example.demo.repositories.UserRepository;
import com.example.demo.requests.LoginRequest;
import com.example.demo.requests.RegisterRequest;
import com.example.demo.requests.TokenRequest;
import com.example.demo.services.TokenService;
import com.example.demo.model.RefreshToken;
import com.example.demo.model.User;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
public class AuthController {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final RefreshTokenRepository tokenRepo;

    public AuthController(UserRepository userRepo, PasswordEncoder passwordEncoder,
            TokenService tokenService, RefreshTokenRepository tokenRepo) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.tokenRepo = tokenRepo;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest req) {

        Optional<User> optionalUser = userRepo.getByEmail(req.email());

        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid email or password"));
        }

        User user = optionalUser.get();

        if (!passwordEncoder.matches(req.password(), user.password())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid email or password"));
        }

        // User authenticated successfully
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        Authentication authUser = new UsernamePasswordAuthenticationToken(user, null, authorities);

        String accessToken = tokenService.generateAccessToken(authUser);
        String refreshToken = tokenService.generateRefreshToken(authUser);

        RefreshToken tokenModel = new RefreshToken(null, user.id(), refreshToken);
        tokenRepo.save(tokenModel);

        return ResponseEntity.ok(Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken));
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest req) {

        if (userRepo.existsByEmail(req.email())) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("message", "Email already registered."));
        }

        String encodedPassword = passwordEncoder.encode(req.password());
        User user = User.create(req.firstName(), req.lastName(), req.email(), encodedPassword, 2);
        userRepo.save(user);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "User registered successfully!"));
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<Map<String, Object>> tokenRefresh(@RequestBody TokenRequest req, Authentication auth) {

        Jwt jwt = (Jwt) auth.getPrincipal();
        Long userId = jwt.getClaim("id");

        if (tokenRepo.existsById(userId)) {
            String accessToken = tokenService.generateAccessToken(auth);
            return ResponseEntity.ok(Map.of("accessToken", accessToken));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Invalid token!"));
    }

    
}
