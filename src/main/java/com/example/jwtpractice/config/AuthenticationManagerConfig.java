package com.example.jwtpractice.config;

import com.example.jwtpractice.security.jwt.filter.JwtAuthenticationFilter;
import com.example.jwtpractice.security.jwt.provider.JwtAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class AuthenticationManagerConfig extends AbstractHttpConfigurer<AuthenticationManagerConfig, HttpSecurity> {
    // JWT 인증 처리 Provider
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        // AuthenticationManager 생성
        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

        // Jwt 필터를 Username...Filter 앞에 추가
        builder.addFilterBefore(
                        new JwtAuthenticationFilter(authenticationManager),
                        UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(jwtAuthenticationProvider);
    }
}