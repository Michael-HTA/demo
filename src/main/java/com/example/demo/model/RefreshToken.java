package com.example.demo.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Table("refreshtokens")
public record RefreshToken(
    @Id Long id,
    @Column("user_id") Long userId,
    @Column("token") String token
) {}
