package com.accenture.sast.tracker.service;

import com.accenture.sast.tracker.model.AppUser;
import com.accenture.sast.tracker.repository.AppUserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@Service
public class AuthService {

    // ── VULNERABILITY V3: Hardcoded Secret (CWE-798) ──────────────────────────
    // A secret embedded in source code is committed to version control and
    // visible to anyone with repository access.
    // Fix: load from an environment variable or a secrets manager, never from code.
    // ──────────────────────────────────────────────────────────────────────────
    private static final String API_SECRET = System.getenv("API_SECRET");

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    private final AppUserRepository userRepository;

    public AuthService(AppUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ── VULNERABILITY V2: Weak Cryptography (CWE-327) ─────────────────────────
    // MD5 is a broken hash function: it is fast to compute and has known collision
    // attacks.  Passwords hashed with MD5 can be cracked from a 10-billion-entry
    // rainbow table in seconds.
    // Fix: use BCrypt, Argon2, or PBKDF2 — all supported by Spring Security's
    //      PasswordEncoder interface.
    // ──────────────────────────────────────────────────────────────────────────
    public String hashPassword(String password) {
        return encoder.encode(password);
    }

    public AppUser register(String username, String password) {
        String hash = hashPassword(password);
        return userRepository.save(new AppUser(username, hash));
    }

    public boolean authenticate(String username, String password) {
        Optional<AppUser> user = userRepository.findByUsername(username);
        if (user.isEmpty()) return false;
        return encoder.matches(password, user.get().getPasswordHash());  
    }

    public String getApiSecret() {
        return API_SECRET;
    }
}
