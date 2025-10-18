package com.auth.server.controller;

import com.auth.server.model.User;
import com.auth.server.service.UserService;
import com.auth.server.util.JwtResponse;
import com.auth.server.util.SignInRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
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
            return ResponseEntity.status(401).build();
        }
    }


    @PostMapping("/oauth2/success")
    public ResponseEntity<Map<String, Object>> handleOAuth2Success(HttpServletRequest request) {
        try {
            User user = (User) request.getAttribute("user");
            if (user == null) {
                return ResponseEntity.badRequest().build();
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
                    )
            ));
        } catch (Exception ex) {
            log.error("OAuth2 success handling failed", ex);
            return ResponseEntity.status(500).build();
        }
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(HttpServletRequest request) {
        try {
            User user = (User) request.getAttribute("user");
            if (user == null) {
                return ResponseEntity.status(401).build();
            }

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
            return ResponseEntity.status(500).build();
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logoutUser() {
        // In stateless JWT architecture, token validation happens on the client side
        // Server can't invalidate tokens, so this endpoint is informational
        return ResponseEntity.ok("Logout successful. Please remove token from client storage.");
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
}