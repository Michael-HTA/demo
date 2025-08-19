package com.example.demo.repositories;

import org.springframework.data.repository.CrudRepository;
import com.example.demo.model.RefreshToken;


public interface RefreshTokenRepository extends CrudRepository<RefreshToken,Long> {
    public boolean existsByUserId(int userId);
}
