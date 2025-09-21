package com.fuelwise.app.auth.web.dto;

public record AuthResponse(
    String accessToken,
    String refreshToken,
    String tokenType
) {}
