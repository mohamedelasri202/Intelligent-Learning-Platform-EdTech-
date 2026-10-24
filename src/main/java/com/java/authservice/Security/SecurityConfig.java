package com.java.authservice.Security;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
         http
                 .csrf(csrf-> csrf.disable())
                 .authorizeHttpRequests(auth -> auth
                         .requestMatchers("/login", "/register").permitAll()
                         .requestMatchers("/admin/**").hasRole("ADMIN")
                         .anyRequest().authenticated());


         return  http.build();

    }








}
