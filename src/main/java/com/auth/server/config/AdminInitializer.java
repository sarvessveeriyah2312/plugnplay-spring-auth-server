package com.auth.server.config;

import com.auth.server.model.User;
import com.auth.server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class AdminInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // ✅ Read from application.properties
    @Value("${admin.email:admin@system.com}")
    private String adminEmail;

    @Value("${admin.password:Admin@123}")
    private String adminPassword;

    @Value("${admin.fullname:System Administrator}")
    private String adminFullName;

    @Override
    public void run(String... args) {
        log.info("Checking for default admin account...");

        userRepository.findByEmail(adminEmail).ifPresentOrElse(
                existing -> log.info("Admin account already exists: {}", adminEmail),
                () -> {
                    log.info("Creating default admin account...");
                    User admin = User.builder()
                            .email(adminEmail)
                            .fullName(adminFullName)
                            .provider("local")
                            .password(passwordEncoder.encode(adminPassword))
                            .roles(Set.of("ROLE_SUPER_ADMIN")) // ROLE_ADMIN is a superset of ROLE_SUPER_ADMIN, ROLE_USER is a superset of ROLE_SUPER_ADMIN, ROLE_SUPER_ADMIN is a superset of ROLE_USER
                            .enabled(true)
                            .emailVerified(true)
                            .build();

                    userRepository.save(admin);
                    log.info("Default admin account created: {}", adminEmail);
                }
        );
    }
}
