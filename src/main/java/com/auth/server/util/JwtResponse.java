package com.auth.server.util;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record JwtResponse(
        String token,
        String type,
        String email,
        String message
) {
    // Success constructor
    public JwtResponse(String token, String email, String message) {
        this(token, "Bearer", email, message);
    }

    // Error constructor (no token)
    public JwtResponse(String email, String message) {
        this(null, null, email, message);
    }

    // Default constructor for success cases
    public JwtResponse {
        if (type == null) {
            type = "Bearer";
        }
    }
}