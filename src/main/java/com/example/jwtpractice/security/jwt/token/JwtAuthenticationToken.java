package com.example.jwtpractice.security.jwt.token;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private String token;
    private Object principal; // 로그인한 사용자 id , email
    private Object credentials;

    // 주어진 authorities, 사용자 정보 principal, credentials 를 기반으로 인증 토큰 생성
    public JwtAuthenticationToken(Collection<? extends GrantedAuthority> authorities,
                                  Object principal, Object credentials) {
        // 부모 클래스인 AbstractAuthenticationToken 생성자 호출해서 인증 토큰 생성
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;

        // 인증된 상태
        this.setAuthenticated(true);
    }

    // 주어진 JWT token 문자열로 인증 토큰 생성
    public JwtAuthenticationToken(String token) {
        super(null);
        this.token = token;

        // 인증된 상태가 아님을 나타냄
        this.setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
