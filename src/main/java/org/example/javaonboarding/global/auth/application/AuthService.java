package org.example.javaonboarding.global.auth.application;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import org.example.javaonboarding.global.entity.RefreshToken;
import org.example.javaonboarding.global.jwt.JWTUtil;
import org.example.javaonboarding.global.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;

import java.util.Date;

import static org.example.javaonboarding.global.jwt.LoginFilter.ACCESS_TOKEN_EXPIRATION_TIME;
import static org.example.javaonboarding.global.jwt.LoginFilter.REFRESH_TOKEN_EXPIRATION_TIME;

@Service
public class AuthService {

    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthService(JWTUtil jwtUtil, RefreshTokenRepository refreshTokenRepository) {
        this.jwtUtil = jwtUtil;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public String[] reissue(Cookie[] cookies) {
        String[] tokens = new String[2];

        // Refresh Token 얻기
        String refresh = null;
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {
            throw new IllegalArgumentException("refresh token null");
        }

        // 만료 체크
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            throw new IllegalArgumentException("refresh token expired");
        }

        // 토큰이 refresh인지 확인
        String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {
            throw new IllegalArgumentException("invalid refresh token");
        }

        // DB에 저장이 되어 있는지 확인
        Boolean isExist = refreshTokenRepository.existsByRefresh(refresh);
        if (!isExist) {
            throw new IllegalArgumentException("invalid refresh token");
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // 새로운 JWT 생성
        String newAccess = jwtUtil.createJwt("access", username, role, ACCESS_TOKEN_EXPIRATION_TIME);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, REFRESH_TOKEN_EXPIRATION_TIME);

        // 새로 만든 refresh 토큰 DB에 저장, 기존 refresh 토큰은 삭제
        refreshTokenRepository.deleteByRefresh(refresh);
        addRefreshToken(username, newRefresh, REFRESH_TOKEN_EXPIRATION_TIME);

        tokens[0] = newAccess;
        tokens[1] = newRefresh;

        return tokens;
    }

    private void addRefreshToken(String username, String newRefresh, long expiredMs) {
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUsername(username);
        refreshToken.setRefresh(newRefresh);
        refreshToken.setExpiration(date.toString());

        refreshTokenRepository.save(refreshToken);
    }
}
