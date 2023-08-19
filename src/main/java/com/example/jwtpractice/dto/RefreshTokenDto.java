package com.example.jwtpractice.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class RefreshTokenDto {
    @NotEmpty
    String refreshToken;
}
