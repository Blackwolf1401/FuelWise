package com.fuelwise.app.auth.security;

import java.io.IOException;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fuelwise.app.auth.repository.UserRepository;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserRepository userRepo;

    public JwtAuthFilter(JwtService jwtService, UserRepository userRepo){
    this.jwtService = jwtService; this.userRepo = userRepo;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
        throws ServletException, IOException {
    String header = req.getHeader("Authorization");
    if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
        String token = header.substring(7);
        try {
        var jws = jwtService.parse(token);
        Claims c = jws.getBody();
        var email = c.getSubject();
        var user = userRepo.findByEmail(email).orElse(null);
        if (user != null && user.isEnabled()) {
            var authorities = user.getRoles().stream()
            .map(r -> new SimpleGrantedAuthority("ROLE_" + r.getName()))
            .collect(Collectors.toSet());
            var auth = new UsernamePasswordAuthenticationToken(email, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        } catch (Exception ignored) { /* token inválido: request queda anónima */ }
    }
    chain.doFilter(req, res);
    }
}
