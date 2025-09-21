package com.fuelwise.app.auth.security;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtService {
    private final Key key;
    private final String issuer;
    private final long accessMinutes;
    private final long refreshDays;

    public JwtService(
        @Value("${app.jwt.secret}") String secret,
        @Value("${app.jwt.issuer}") String issuer,
        @Value("${app.jwt.access-minutes}") long accessMinutes,
        @Value("${app.jwt.refresh-days}") long refreshDays
    ){
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("app.jwt.secret is missing");
        }
        byte[] keyBytes;
        if (secret.startsWith("base64:")) {
            keyBytes = java.util.Base64.getDecoder().decode(secret.substring(7));
        } else {
            keyBytes = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
        if (keyBytes.length < 32) {
            throw new IllegalArgumentException("app.jwt.secret must be at least 32 bytes for HS256");
        }
        this.key = io.jsonwebtoken.security.Keys.hmacShaKeyFor(keyBytes);
        this.issuer = issuer;
        this.accessMinutes = accessMinutes;
        this.refreshDays = refreshDays;
    }

    public String generateAccess(String subject, Map<String, Object> claims){
    Instant now = Instant.now();
    return Jwts.builder()
        .setId(UUID.randomUUID().toString())
        .setSubject(subject)
        .setIssuer(issuer)
        .addClaims(claims)
        .setIssuedAt(Date.from(now))
        .setExpiration(Date.from(now.plusSeconds(accessMinutes * 60)))
        .signWith(key, SignatureAlgorithm.HS256)
        .compact();
    }

    public String generateRefresh(String subject){
    Instant now = Instant.now();
    return Jwts.builder()
        .setId(UUID.randomUUID().toString())
        .setSubject(subject)
        .setIssuer(issuer)
        .claim("typ","refresh")
        .setIssuedAt(Date.from(now))
        .setExpiration(Date.from(now.plusSeconds(refreshDays * 86400)))
        .signWith(key, SignatureAlgorithm.HS256)
        .compact();
    }

    public Jws<Claims> parse(String token){
    return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }
}
