package com.example.jwtpractice.controller;

import com.example.jwtpractice.domain.Member;
import com.example.jwtpractice.domain.RefreshToken;
import com.example.jwtpractice.domain.Role;
import com.example.jwtpractice.dto.*;
import com.example.jwtpractice.security.jwt.util.JwtTokenizer;
import com.example.jwtpractice.service.MemberService;
import com.example.jwtpractice.service.RefreshTokenService;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@Validated
@RequestMapping("/members")
public class MemberController {
    private final JwtTokenizer jwtTokenizer;
    private final PasswordEncoder passwordEncoder;
    private final MemberService memberService;
    private final RefreshTokenService refreshTokenService;


    @PostMapping("/signup")
    public ResponseEntity signup(@RequestBody @Valid MemberSignupDto memberSignupDto,
                                 BindingResult bindingResult) {

        // 유효성 검증 실패시 익셉션 터뜨리기
        if (bindingResult.hasErrors()) {
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        Member member = new Member();
        member.setName(memberSignupDto.getName());
        member.setEmail(memberSignupDto.getEmail());
        member.setPassword(passwordEncoder.encode(memberSignupDto.getPassword()));
        member.setBirthYear(Integer.parseInt(memberSignupDto.getBirthYear()));
        member.setBirthMonth(Integer.parseInt(memberSignupDto.getBirthMonth()));
        member.setBirthDay(Integer.parseInt(memberSignupDto.getBirthDay()));
        member.setGender(memberSignupDto.getGender());

        Member saveMember = memberService.addMember(member);

        MemberSignupResponseDto memberSignupResponse = new MemberSignupResponseDto();
        memberSignupResponse.setMemberId(saveMember.getMemberId());
        memberSignupResponse.setName(saveMember.getName());
        memberSignupResponse.setRegdate(saveMember.getRegdate());
        memberSignupResponse.setEmail(saveMember.getEmail());

        System.out.println("MemberController.signup");

        // 회원가입
        return new ResponseEntity(memberSignupResponse, HttpStatus.CREATED);
    }


    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Valid MemberLoginDto loginDto,
                                BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        // email이 없을 경우 Exception 발생
        Member member = memberService.findByEmail(loginDto.getEmail());

        // 비밀번호가 일치하는지 확인
        if (!passwordEncoder.matches(loginDto.getPassword(), member.getPassword())) {
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        // List<Role> ===> List<String>
        List<String> roles = member.getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        // JWT 토큰 발급
        String accessToken = jwtTokenizer.createAccessToken(member.getMemberId(), member.getEmail(), roles);
        String refreshToken = jwtTokenizer.createRefreshToken(member.getMemberId(), member.getEmail(), roles);

        // RefreshToken DB 저장 - 성능때문에 DB가 아닌 Redis에 저장하는 것이 좋음
        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setValue(refreshToken);
        refreshTokenEntity.setMemberId(member.getMemberId());
        refreshTokenService.addRefreshToken(refreshTokenEntity);

        MemberLoginResponseDto loginResponse = MemberLoginResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .memberId(member.getMemberId())
                .nickname(member.getName())
                .build();

        return new ResponseEntity(loginResponse, HttpStatus.OK);
    }

    @DeleteMapping("/logout")
    public ResponseEntity logout(@RequestBody RefreshTokenDto refreshTokenDto) {
        refreshTokenService.deleteRefreshToken(refreshTokenDto.getRefreshToken());
        return new ResponseEntity(HttpStatus.OK);
    }

    @PostMapping("/refreshToken")
    public ResponseEntity requestRefresh(@RequestBody RefreshTokenDto refreshTokenDto) {
        // 받은 refreshToken으로 DB에서 refresh 엔티티 조회
        RefreshToken refreshToken = refreshTokenService.findRefreshToken(refreshTokenDto.getRefreshToken())
                .orElseThrow(() ->
                        new IllegalArgumentException("Refresh token not found")
                );

        // refreshToken으로부터 claims 추출 후 memberId 추출
        Claims claims = jwtTokenizer.parseRefreshToken(refreshToken.getValue());
        Long memberId = Long.valueOf((Integer) claims.get("memberId"));

        // 추출한 memberId로 회원 정보 조회
        Member member = memberService.getMember(memberId).orElseThrow(() -> {
            throw new IllegalArgumentException("Member not found");
        });

        // accessToken 재발급 받기 위한 정보 추출
        List roles = (List) claims.get("roles");
        String email = claims.getSubject();

        // accessToken 재발급
        String accessToken = jwtTokenizer.createAccessToken(memberId, email, roles);

        // MemberLoginResponseDto 반환
        MemberLoginResponseDto loginResponse = MemberLoginResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenDto.getRefreshToken())
                .memberId(member.getMemberId())
                .nickname(member.getName())
                .build();
        return new ResponseEntity(loginResponse, HttpStatus.OK);
    }
}
