package com.auth.server.util;

public record JwtResponse(
        String token,
        String email,
        String message
) {}
