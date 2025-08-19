package com.example.demo.repositories;

import java.util.Optional;
import org.springframework.data.repository.CrudRepository;

import com.example.demo.model.User;


public interface UserRepository extends CrudRepository<User, Long> {
    public Optional<User> getByEmail(String email);
    public boolean existsByEmail(String email);
}
