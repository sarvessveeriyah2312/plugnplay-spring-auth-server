package com.auth.server.service;

import com.auth.server.config.JwtUtilsConfig;
import com.auth.server.model.User;
import com.auth.server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtilsConfig jwtUtilsConfig;

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
        return userRepository.findByProviderAndProviderId(provider, providerId);
    }

    public User findOrCreateUser(OAuth2User oauth2User, String provider) {
        Map<String, Object> attributes = oauth2User.getAttributes();

        String email = extractEmail(attributes, provider);
        String providerId = extractProviderId(attributes, provider);
        String fullName = extractFullName(attributes, provider);
        String imageUrl = extractImageUrl(attributes, provider);

        return findByProviderAndProviderId(provider, providerId)
                .orElseGet(() -> {
                    log.info("Creating new user - provider: {}, email: {}", provider, email);
                    User user = new User();
                    user.setEmail(email);
                    user.setFullName(fullName);
                    user.setProvider(provider);
                    user.setProviderId(providerId);
                    user.setImageUrl(imageUrl);
                    user.setEmailVerified(isEmailVerified(attributes, provider));
                    return userRepository.save(user);
                });
    }

    public String authenticate(String email, String password) {
        try {
            AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            return jwtUtilsConfig.generateToken(userDetails);
        } catch (Exception ex) {
            throw new RuntimeException("Authentication failed: " + ex.getMessage());
        }
    }


    public String generateJwtToken(User user) {
        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password("") // OAuth users don't have passwords
                .roles("USER")
                .build();

        return jwtUtilsConfig.generateToken(userDetails, Map.of(
                "userId", user.getUid(),
                "fullName", user.getFullName(),
                "provider", user.getProvider(),
                "imageUrl", user.getImageUrl()
        ));
    }

    private String extractEmail(Map<String, Object> attributes, String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> (String) attributes.get("email");
            case "github" -> (String) attributes.getOrDefault("email", attributes.get("login") + "@users.noreply.github.com");
            case "microsoft" -> (String) attributes.get("mail");
            default -> (String) attributes.get("email");
        };
    }

    private String extractProviderId(Map<String, Object> attributes, String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> (String) attributes.get("sub");
            case "github" -> (String) attributes.get("id").toString();
            case "microsoft" -> (String) attributes.get("oid");
            default -> (String) attributes.get("id");
        };
    }

    private String extractFullName(Map<String, Object> attributes, String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> (String) attributes.get("name");
            case "github" -> (String) attributes.getOrDefault("name", (String) attributes.get("login"));
            case "microsoft" -> (String) attributes.get("displayName");
            default -> (String) attributes.get("name");
        };
    }

    private String extractImageUrl(Map<String, Object> attributes, String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> (String) attributes.get("picture");
            case "github" -> (String) attributes.get("avatar_url");
            case "microsoft" -> (String) attributes.get("photo");
            default -> (String) attributes.get("picture");
        };
    }

    private boolean isEmailVerified(Map<String, Object> attributes, String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> Boolean.TRUE.equals(attributes.get("email_verified"));
            case "github" -> false; // GitHub doesn't provide email verification for public email
            case "microsoft" -> true; // Microsoft email is typically verified
            default -> false;
        };
    }
}