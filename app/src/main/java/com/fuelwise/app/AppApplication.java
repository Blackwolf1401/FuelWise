package com.fuelwise.app;

import java.util.Set;                       // <-- IMPORT

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.fuelwise.app.auth.domain.User;   // <-- IMPORT
import com.fuelwise.app.auth.repository.RoleRepository;
import com.fuelwise.app.auth.repository.UserRepository;

@SpringBootApplication
public class AppApplication {
	public static void main(String[] args) {
	SpringApplication.run(AppApplication.class, args);
	}

	@Bean
	CommandLineRunner seed(RoleRepository roles, UserRepository users, PasswordEncoder enc) {
	return args -> {
		var adminRole = roles.findByName("ADMIN").orElse(null);
		var userRole  = roles.findByName("USER").orElse(null);
		if (adminRole == null || userRole == null) return; // creados por Flyway

		users.findByEmail("admin@fuelwise.local").orElseGet(() -> {
		var u = new User();
		u.setEmail("admin@fuelwise.local");
		u.setPasswordHash(enc.encode("admin123"));
		u.setRoles(Set.of(adminRole, userRole));
		return users.save(u);
		});
	};
	}
}
