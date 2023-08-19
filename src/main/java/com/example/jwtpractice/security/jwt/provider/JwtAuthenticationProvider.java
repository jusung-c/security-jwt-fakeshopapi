package com.example.jwtpractice.security.jwt.provider;

import com.example.jwtpractice.security.jwt.token.JwtAuthenticationToken;
import com.example.jwtpractice.security.jwt.util.JwtTokenizer;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtTokenizer jwtTokenizer;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;

        // 토큰 검증 (기간이 만료되었는지, 토큰 문자열이 문제가 있는지 등)
        Claims claims = jwtTokenizer.parseAccessToken(authenticationToken.getToken());

        // sub를 암호화해서 넣었다면 여기서 복호화하는 코드가 필요하다
        // ...

        // 토큰에서 정보 추출
        String email = claims.getSubject();
        Long memberId = claims.get("memberId", Long.class);
        String name = claims.get("name", String.class);

        // 권한 목록 조회
        List<GrantedAuthority> authorities = getGrantedAuthorities(claims);

        LoginInfoDto loginInfo = new LoginInfoDto();
        loginInfo.setMemberId(memberId);
        loginInfo.setEmail(email);
        loginInfo.setName(name);

        return new JwtAuthenticationToken(authorities, loginInfo, null);
    }

    private List<GrantedAuthority> getGrantedAuthorities(Claims claims) {
        List<String> roles = (List<String>) claims.get("roles");
        List<GrantedAuthority> authorities = new ArrayList<>();

        for (String role : roles) {
            authorities.add(() -> role);
        }
        return authorities;
    }
}
