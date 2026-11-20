package com.accenture.sast.tracker.controller;

import com.accenture.sast.tracker.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");
        authService.register(username, password);
        return ResponseEntity.ok(Map.of("message", "User registered"));
    }

    // ── VULNERABILITY V4: Sensitive Data in Logs (CWE-532) ───────────────────
    // The plaintext password is written to the application log.
    // Log files are often forwarded to centralised systems (Splunk, ELK) where
    // they can be read by many people and stored indefinitely.
    // Fix: log only the username; never log credentials or tokens.
    // ─────────────────────────────────────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        log.info("Login attempt: username={}", username);

        if (authService.authenticate(username, password)) {
            return ResponseEntity.ok(Map.of("message", "Login successful",
                                             "token", authService.getApiSecret()));
        }
        return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials"));
    }
}
