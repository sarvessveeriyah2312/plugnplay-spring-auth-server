package com.auth.server.service;

import com.auth.server.model.User;
import com.auth.server.repository.UserRepository;
import com.auth.server.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtils jwtUtils; // ✅ Changed to JwtUtils

    // =====================================================
    // USER RETRIEVAL
    // =====================================================

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
        return userRepository.findByProviderAndProviderId(provider, providerId);
    }

    // =====================================================
    // OAUTH USER CREATION
    // =====================================================

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

    // =====================================================
    // LOCAL AUTHENTICATION (EMAIL + PASSWORD)
    // =====================================================

    public String authenticate(String email, String password) {
        try {
            AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // ✅ Use the method that includes actual roles from UserDetails
            return jwtUtils.generateToken(userDetails.getUsername(), userDetails.getAuthorities());

        } catch (Exception ex) {
            log.error("Authentication failed for {}: {}", email, ex.getMessage());
            throw new RuntimeException("Authentication failed: " + ex.getMessage(), ex);
        }
    }

    // =====================================================
    // TOKEN GENERATION FOR OAUTH USERS
    // =====================================================

    public String generateJwtToken(User user) {
        // ✅ Load the full user with roles from database
        User fullUser = userRepository.findByEmail(user.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found: " + user.getEmail()));

        // Convert User roles to GrantedAuthority and generate token with actual roles
        var authorities = fullUser.getAuthorities().stream()
                .map(role -> new SimpleGrantedAuthority(role.getAuthority()))
                .collect(Collectors.toList());

        return jwtUtils.generateToken(fullUser.getEmail(), authorities);
    }

    // =====================================================
    // ATTRIBUTE EXTRACTION HELPERS
    // =====================================================

    private String extractEmail(Map<String, Object> attributes, String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> (String) attributes.get("email");
            case "github" -> (String) attributes.getOrDefault("email",
                    attributes.get("login") + "@users.noreply.github.com");
            case "microsoft" -> (String) attributes.get("mail");
            default -> (String) attributes.get("email");
        };
    }

    private String extractProviderId(Map<String, Object> attributes, String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> (String) attributes.get("sub");
            case "github" -> attributes.get("id").toString();
            case "microsoft" -> (String) attributes.get("oid");
            default -> (String) attributes.get("id");
        };
    }

    private String extractFullName(Map<String, Object> attributes, String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> (String) attributes.get("name");
            case "github" -> (String) attributes.getOrDefault("name", attributes.get("login"));
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
            case "github" -> false;
            case "microsoft" -> true;
            default -> false;
        };
    }
    /**
     * Generate JWT token with roles from User entity
     */
    private String generateTokenWithRoles(User user) {
        // Extract roles from User entity
        var roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        log.debug("Generating token for user: {} with roles: {}", user.getEmail(), roles);

        return jwtUtils.generateToken(user.getEmail(), roles);
    }
}