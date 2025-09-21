package com.fuelwise.app.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fuelwise.app.auth.repository.UserRepository;
import com.fuelwise.app.auth.security.JwtAuthFilter;
import com.fuelwise.app.auth.security.JwtService;

@Configuration
public class SecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(UserRepository repo) {
    return email -> repo.findByEmail(email)
        .map(u -> org.springframework.security.core.userdetails.User     // <-- usar la clase de Spring Security
        .withUsername(u.getEmail())
        .password(u.getPasswordHash())
        .authorities(u.getRoles().stream()
            .map(r -> "ROLE_" + r.getName())
            .toArray(String[]::new))
        .accountLocked(!u.isEnabled())
        .build())
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    DaoAuthenticationProvider authProvider(UserDetailsService uds, PasswordEncoder pe) {
        var p = new DaoAuthenticationProvider();
        p.setUserDetailsService(uds);
        p.setPasswordEncoder(pe);
        return p;
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, JwtService jwt, UserRepository repo) throws Exception {
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(sm -> sm.sessionCreationPolicy(
            org.springframework.security.config.http.SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/**").permitAll()
            .requestMatchers("/api/auth/login", "/api/auth/register", "/api/auth/refresh").permitAll()
            .anyRequest().authenticated()
        );

        // Si ya tienes tu JwtAuthFilter:
        http.addFilterBefore(new JwtAuthFilter(jwt, repo), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
