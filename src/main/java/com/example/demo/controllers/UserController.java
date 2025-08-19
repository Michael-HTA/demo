package com.example.demo.controllers;

import java.security.Principal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.demo.dto.User;
import com.example.demo.repositories.UserRepository;

@RestController
public class UserController {
    private final UserRepository repo;

    public UserController(UserRepository repo) {
        this.repo = repo;
    }

    @GetMapping
    public String sayHello(Principal principal) {
        return "Hello ";
    }

    @GetMapping("/user")
    public ResponseEntity<User> getMethodName() {
        return repo.findById(1L).map(u -> new User(u.firstName(), u.lastName(), u.email()))
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/isTrue")
    public ResponseEntity<User> getSomething(Authentication auth) {
        Jwt jwt = (Jwt) auth.getPrincipal();
        String email = jwt.getSubject();
        // String scope = jwt.getClaimAsString("scope");

        ResponseEntity<User> user = repo.getByEmail(email).map(u -> new User(u.firstName(), u.lastName(), u.email()))
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());

        // return new ResponseEntity<Object>(scope, HttpStatusCode.valueOf(200));
        return user;
    }

}
