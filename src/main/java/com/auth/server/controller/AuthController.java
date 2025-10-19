package com.auth.server.controller;

import com.auth.server.model.User;
import com.auth.server.service.UserService;
import com.auth.server.util.JwtResponse;
import com.auth.server.util.SignInRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000,http://localhost:4200")
public class AuthController {

    private final UserService userService;

    @PostMapping("/signin")
    public ResponseEntity<JwtResponse> authenticateUser(@RequestBody SignInRequest signInRequest) {
        try {
            String jwt = userService.authenticate(signInRequest.email(), signInRequest.password());
            return ResponseEntity.ok(
                    new JwtResponse(jwt, signInRequest.email(), "Login successful")
            );
        } catch (Exception ex) {
            log.error("Authentication failed for user: {}", signInRequest.email(), ex);
            return ResponseEntity.status(401).body(
                    new JwtResponse(null, signInRequest.email(), "Authentication failed: " + ex.getMessage())
            );
        }
    }

    @PostMapping("/oauth2/success")
    public ResponseEntity<Map<String, Object>> handleOAuth2Success(HttpServletRequest request) {
        try {
            User user = (User) request.getAttribute("user");
            if (user == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "User not found in request"));
            }

            String jwt = userService.generateJwtToken(user);
            return ResponseEntity.ok(Map.of(
                    "token", jwt,
                    "user", Map.of(
                            "id", user.getUid(),
                            "email", user.getEmail(),
                            "fullName", user.getFullName(),
                            "provider", user.getProvider(),
                            "imageUrl", user.getImageUrl(),
                            "emailVerified", user.isEmailVerified()
                    ),
                    "message", "OAuth2 authentication successful"
            ));
        } catch (Exception ex) {
            log.error("OAuth2 success handling failed", ex);
            return ResponseEntity.status(500).body(Map.of("error", "OAuth2 authentication failed"));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated() ||
                    authentication.getPrincipal().equals("anonymousUser")) {
                return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
            }

            // Get user details from SecurityContext
            Object principal = authentication.getPrincipal();
            String username;

            if (principal instanceof UserDetails) {
                username = ((UserDetails) principal).getUsername();
            } else if (principal instanceof String) {
                username = (String) principal;
            } else {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid authentication"));
            }

            // Load user from database to get full details
            User user = userService.findByEmail(username)
                    .orElseThrow(() -> new RuntimeException("User not found: " + username));

            return ResponseEntity.ok(Map.of(
                    "id", user.getUid(),
                    "email", user.getEmail(),
                    "fullName", user.getFullName(),
                    "provider", user.getProvider(),
                    "imageUrl", user.getImageUrl(),
                    "emailVerified", user.isEmailVerified(),
                    "enabled", user.isEnabled(),
                    "authorities", user.getAuthorities()
            ));
        } catch (Exception ex) {
            log.error("Failed to get current user", ex);
            return ResponseEntity.status(500).body(Map.of("error", "Failed to get user details"));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logoutUser() {
        // Clear the security context
        SecurityContextHolder.clearContext();

        return ResponseEntity.ok(Map.of(
                "message", "Logout successful. Please remove token from client storage."
        ));
    }

    @GetMapping("/providers")
    public ResponseEntity<Map<String, Object>> getAvailableProviders() {
        return ResponseEntity.ok(Map.of(
                "providers", Map.of(
                        "google", Map.of(
                                "name", "Google",
                                "scope", "openid email profile",
                                "authorizationUrl", "/oauth2/authorization/google"
                        ),
                        "github", Map.of(
                                "name", "GitHub",
                                "scope", "user:email",
                                "authorizationUrl", "/oauth2/authorization/github"
                        ),
                        "microsoft", Map.of(
                                "name", "Microsoft",
                                "scope", "User.Read",
                                "authorizationUrl", "/oauth2/authorization/microsoft"
                        )
                )
        ));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        return ResponseEntity.ok(Map.of("status", "OK", "service", "Auth Service"));
    }
}