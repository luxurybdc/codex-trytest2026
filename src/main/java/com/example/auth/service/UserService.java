package com.example.auth.service;

import com.example.auth.model.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class UserService {

    private final Map<String, User> users = new ConcurrentHashMap<>();
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public boolean register(String username, String rawPassword) {
        String normalized = username.trim();
        if (users.containsKey(normalized)) {
            return false;
        }
        User user = new User(normalized, passwordEncoder.encode(rawPassword));
        users.put(normalized, user);
        return true;
    }

    public boolean authenticate(String username, String rawPassword) {
        User user = users.get(username.trim());
        return user != null && passwordEncoder.matches(rawPassword, user.getPasswordHash());
    }

    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }
}
