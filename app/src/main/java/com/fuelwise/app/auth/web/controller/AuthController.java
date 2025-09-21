package com.fuelwise.app.auth.web.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fuelwise.app.auth.service.AuthService;      // <-- IMPORT NECESARIO
import com.fuelwise.app.auth.web.dto.AuthResponse;
import com.fuelwise.app.auth.web.dto.LoginRequest;
import com.fuelwise.app.auth.web.dto.RegisterRequest;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;
    public AuthController(AuthService authService){ this.authService = authService; }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest req){
    return ResponseEntity.ok(authService.register(req));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req){
    return ResponseEntity.ok(authService.login(req));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestHeader("Authorization") String bearer){
    return ResponseEntity.ok(authService.refresh(bearer));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(){
    return ResponseEntity.ok(authService.me());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String bearer){
    authService.logout(bearer);
    return ResponseEntity.noContent().build();
    }
}
