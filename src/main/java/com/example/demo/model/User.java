package com.example.demo.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Table("users")
public record User(
        @Id Long id,
        @Column("first_name") String firstName,
        @Column("last_name") String lastName,
        String email,
        String password,
        @Column("role_id") int roleId) {
    public static User create(String firstName, String lastName, String email, String password, int roleId) {
        return new User(null, firstName, lastName, email, password, roleId);
    }
}
