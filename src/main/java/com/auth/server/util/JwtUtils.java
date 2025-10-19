package com.auth.server.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * ✅ JWT Utility using HS256 symmetric encryption
 * -------------------------------------------------------------
 * - Uses single shared secret key for signing & validation
 * - Simpler than RS256; suitable for single-service systems
 * - Compatible with Postman / frontend testing
 */
@Slf4j
@Component
public class JwtUtils {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        try {
            // ✅ Convert Base64 secret to SecretKey (consistent with JwtTokenProvider)
            this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
            log.info("✅ HS256 Secret Key successfully initialized");
        } catch (Exception e) {
            throw new IllegalStateException("❌ Failed to initialize HS256 secret key", e);
        }
    }

    /** ✅ Generate JWT token for a given username with roles */
    public String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        List<String> roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        log.debug("Generating JWT token for user: {} with roles: {}", username, roles);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .claim("roles", roles) // Add roles to JWT
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /** ✅ Generate JWT token for a given username with string roles */
    public String generateToken(String username, List<String> roles) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        log.debug("Generating JWT token for user: {} with roles: {}", username, roles);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .claim("roles", roles) // Add roles to JWT
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /** ✅ Generate simple JWT token for a given username (backward compatibility) */
    public String generateToken(String username) {
        // Default to ROLE_USER if no roles provided
        return generateToken(username, List.of("ROLE_USER"));
    }

    /** ✅ Extract roles from JWT token */
    public List<String> extractRoles(String token) {
        try {
            Claims claims = parseClaims(token);
            List<String> roles = claims.get("roles", List.class);

            if (roles != null && !roles.isEmpty()) {
                log.debug("Extracted roles from JWT: {}", roles);
                return roles;
            }
        } catch (Exception e) {
            log.warn("⚠️ No roles found in JWT token or error extracting roles: {}", e.getMessage());
        }

        // Fallback to default role
        log.debug("No roles found in JWT, using default ROLE_USER");
        return List.of("ROLE_USER");
    }

    /** ✅ Extract specific role claim */
    public List<String> extractClaimAsStringList(String token, String claimName) {
        try {
            Claims claims = parseClaims(token);
            return claims.get(claimName, List.class);
        } catch (Exception e) {
            log.warn("⚠️ Could not extract claim '{}' from JWT: {}", claimName, e.getMessage());
            return List.of();
        }
    }

    /** ✅ Validate JWT signature and expiration */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.error("❌ JWT expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("❌ Unsupported JWT: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("❌ Malformed JWT: {}", e.getMessage());
        } catch (SignatureException e) {
            log.error("❌ Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("❌ JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            log.error("❌ JWT validation error: {}", e.getMessage());
        }
        return false;
    }

    /** ✅ Extract username (subject) */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /** ✅ Extract any claim generically */
    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = parseClaims(token);
        return resolver.apply(claims);
    }

    /** ✅ Parse and validate claims */
    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /** ✅ Extract token expiration time */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /** ✅ Check if token is expired */
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /** ✅ Get all claims from token (for debugging) */
    public Map<String, Object> getAllClaims(String token) {
        return parseClaims(token);
    }
}