package com.example.jwtpractice.config;

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
                        // AuthenticationManager를 주입한 Jwt 필터 생성
                        new JwtAuthenticationFilter(authenticationManager),
                        UsernamePasswordAuthenticationFilter.class)
                // authenticationManager가 jwt Provider를 Provider로 사용하도록 설정
                .authenticationProvider(jwtAuthenticationProvider);
    }
}