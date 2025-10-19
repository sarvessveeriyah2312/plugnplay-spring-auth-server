package com.auth.server.controller;

import com.auth.server.util.JwtUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * ✅ JWKS Controller (for HS256 configuration)
 * ----------------------------------------------------------
 * - HS256 uses a single shared secret key (symmetric)
 * - Public keys cannot be exposed like RS256 (asymmetric)
 * - This endpoint simply returns metadata for compatibility
 *   with JWKS-style discovery URLs.
 * - NEVER expose the actual secret in production.
 */
@RestController
@Configuration
public class JwksController {

    private final JwtUtils jwtUtils;

    public JwksController(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    /**
     * ✅ Simulated JWKS endpoint for HS256.
     * Returns metadata for clients — NOT the real secret key.
     * Useful for OpenID / Resource Server discovery compatibility.
     */
    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getJwksMetadata() {
        return Map.of(
                "kty", "oct",                 // Key type = octet sequence
                "alg", "HS256",               // Algorithm used
                "use", "sig",                 // Key use: signature
                "kid", "auth-server-key",     // Arbitrary key ID
                "issuer", "http://localhost:8080",
                "note", "This server uses HS256 symmetric signing. The shared secret key is not exposed."
        );
    }
}
