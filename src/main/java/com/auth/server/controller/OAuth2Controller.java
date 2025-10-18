package com.auth.server.controller;

import com.auth.server.model.User;
import com.auth.server.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/oauth2")
@RequiredArgsConstructor
public class OAuth2Controller {

    private final UserService userService;

    @GetMapping("/user")
    public Map<String, Object> getUserInfo(@AuthenticationPrincipal OAuth2User oauth2User,
                                          HttpServletRequest request) {
        try {
            if (oauth2User != null) {
                // Extract provider information from OAuth2User attributes
                String provider = "google"; // Default - you need to determine this better
                User user = userService.findOrCreateUser(oauth2User, provider);

                // Add user to request attributes for later use
                request.setAttribute("user", user);

                return Map.of(
                    "status", "success",
                    "user", Map.of(
                        "id", user.getUid(),
                        "email", user.getEmail(),
                        "fullName", user.getFullName(),
                        "provider", user.getProvider(),
                        "imageUrl", user.getImageUrl(),
                        "emailVerified", user.isEmailVerified()
                    )
                );
            }
            return Map.of("status", "error", "message", "No OAuth2 user found");
        } catch (Exception ex) {
            log.error("Error processing OAuth2 user info", ex);
            return Map.of("status", "error", "message", ex.getMessage());
        }
    }

    @GetMapping("/callback")
    public String oauth2Callback() {
        return "OAuth2 callback received. Redirecting to client application...";
    }
}