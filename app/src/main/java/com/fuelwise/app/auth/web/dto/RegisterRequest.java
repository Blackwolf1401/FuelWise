package com.fuelwise.app.auth.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @Email @NotBlank String email,
    @Size(min=8, max=64) String password,
    boolean admin
) {}
