package com.fuelwise.app.auth.service;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fuelwise.app.auth.domain.Role;
import com.fuelwise.app.auth.domain.User;
import com.fuelwise.app.auth.repository.RoleRepository;
import com.fuelwise.app.auth.repository.UserRepository;
import com.fuelwise.app.auth.security.JwtService;
import com.fuelwise.app.auth.web.dto.AuthResponse;
import com.fuelwise.app.auth.web.dto.LoginRequest;
import com.fuelwise.app.auth.web.dto.RegisterRequest;

import jakarta.transaction.Transactional;

@Service
public class AuthService {
    private final AuthenticationManager authManager;
    private final PasswordEncoder encoder;
    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final JwtService jwt;

    public AuthService(AuthenticationManager am, PasswordEncoder enc, UserRepository ur, RoleRepository rr, JwtService jwt){
    this.authManager = am; this.encoder = enc; this.userRepo = ur; this.roleRepo = rr; this.jwt = jwt;
    }

    @Transactional
    public AuthResponse register(RegisterRequest req){
        if (userRepo.existsByEmail(req.email())) throw new IllegalArgumentException("Email already in use");
        Role base = roleRepo.findByName("USER").orElseThrow();
        Set<Role> roles = new HashSet<>(List.of(base));
        if (req.admin()) roles.add(roleRepo.findByName("ADMIN").orElseThrow());

        User u = User.builder()
            .email(req.email())
            .passwordHash(encoder.encode(req.password()))
            .roles(roles)
            .build();
        userRepo.save(u);

        var access = jwt.generateAccess(u.getEmail(), Map.of("roles", roles.stream().map(Role::getName).toList()));
        var refresh = jwt.generateRefresh(u.getEmail());
        return new AuthResponse(access, refresh, "Bearer");
    }

    public AuthResponse login(LoginRequest req){
        Authentication auth = authManager.authenticate(new UsernamePasswordAuthenticationToken(req.email(), req.password()));
        var user = userRepo.findByEmail(req.email()).orElseThrow();
        var access = jwt.generateAccess(user.getEmail(), Map.of("roles", user.getRoles().stream().map(Role::getName).toList()));
        var refresh = jwt.generateRefresh(user.getEmail());
        return new AuthResponse(access, refresh, "Bearer");
    }

public AuthResponse refresh(String bearer){
    if (bearer == null || bearer.isBlank()) {
        throw new IllegalArgumentException("Missing Authorization header");
    }
    // ✅ Java: sin parámetros con nombre
    var token = bearer.startsWith("Bearer ") ? bearer.substring(7) : bearer;

    var claims = jwt.parse(token).getBody();
    if (!"refresh".equals(claims.get("typ"))) {
        throw new IllegalArgumentException("Not a refresh token");
    }

    var email = claims.getSubject();
    var user = userRepo.findByEmail(email).orElseThrow();

    // Opción A (Java 16+): Stream.toList()
    var rolesList = user.getRoles().stream().map(Role::getName).toList();

    // Opción B (si tu IDE se queja): usa Collectors.toList()
    // import java.util.stream.Collectors;
    // var rolesList = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());

    var access  = jwt.generateAccess(user.getEmail(), Map.of("roles", rolesList));
    var refresh = jwt.generateRefresh(user.getEmail());
    // ✅ Java: sin "tokenType:"
    return new AuthResponse(access, refresh, "Bearer");
}

    public Map<String, Object> me(){
    // en un siguiente paso podemos leer de SecurityContext; por ahora mock simple:
    return Map.of("message","Replace with SecurityContext-based 'me' endpoint");
    }

    public void logout(String bearer){
    // Próximo paso: persistir JTI en revoked_tokens y validar en filtro
    }
}
