package com.example.jwtpractice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final AuthenticationManagerConfig authenticationManagerConfig;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 인증에서 JWT를 사용할 것이므로 HttpSession을 사용하지 않는다.
                .sessionManagement(httpSecuritySessionManagementConfigurer ->
                        httpSecuritySessionManagementConfigurer
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // 시큐리티가 제공해주는 ID, PWD를 입력받는 formLogin을 쓰지 않고 직접 ID, PWD를 입력받아 JWT 토큰을 발급받는 방식 사용
                .formLogin(httpSecurityFormLoginConfigurer ->
                        httpSecurityFormLoginConfigurer
                                .disable()
                )
                // CSRF 공격을 막는 방법으로 켜주는 게 안전하지만 불편하므로 disable
                .csrf(csrf -> csrf.disable())
                // CORS 설정 https://gareen.tistory.com/66 참고
                .cors(httpSecurityCorsConfigurer ->
                        httpSecurityCorsConfigurer
                                .configurationSource(corsConfigurationSource()))
                // Basic 인증 비활성화
                .httpBasic(httpSecurityHttpBasicConfigurer ->
                        httpSecurityHttpBasicConfigurer
                                .disable()
                )
                // 요청이 왔을 때 인증 처리 방법 지정
                .authorizeHttpRequests(httpRequest ->
                        httpRequest
                                // 실제 데이터 요청 전 브라우저가 서버로 보내는 사전 검사 요청 모두 허용
                                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                                // 항상 허용할 주소 지정
                                .requestMatchers("/members/signup", "/members/login", "/members/refreshToken").permitAll()
                                // GET 요청시 항상 허용할 주소 지정
                                .requestMatchers(HttpMethod.GET, "/categories/**", "/products/**").permitAll()
                                // 주소 권한 지정
                                .requestMatchers(HttpMethod.GET, "/**").hasAnyRole("USER")
                                .requestMatchers(HttpMethod.POST, "/**").hasAnyRole("USER", "ADMIN")
                                .anyRequest().hasAnyRole("USER", "ADMIN"))
                // 인증이 필요한 리소스에 인증되지 않은 사용자가 접근시 처리 방법 지정
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                        httpSecurityExceptionHandlingConfigurer
                                .authenticationEntryPoint(customAuthenticationEntryPoint)
                )
                // AuthenticationManager 설정 파일 적용
                .apply(authenticationManagerConfig);
        return http.build();
    }

    // Security Cors로 변경 시도
    public CorsConfigurationSource corsConfigurationSource() {
        // url 패턴에 따라 CORS 설정 적용할 수 있게 해주는 클래스
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // CORS 관련 설정을 담기 위한 클래스
        CorsConfiguration config = new CorsConfiguration();
        // 모든 오리진(도메인)에서 온 요청을 허용
        config.addAllowedOrigin("*");
        // 모든 HTTP 메서드를 허용
        config.addAllowedMethod("*");
        // 허용된 HTTP 메서드 목록 설정
        config.setAllowedMethods(List.of("GET", "POST", "DELETE", "PATCH", "OPTIONS", "PUT"));
        // config 등록
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    // 암호를 암호화하거나, 사용자가 입력한 암호가 기존 암호랑 일치하는지 검사할 때 이 Bean을 사용
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
