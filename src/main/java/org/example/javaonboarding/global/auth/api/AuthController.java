package org.example.javaonboarding.global.auth.api;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.javaonboarding.global.auth.application.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.example.javaonboarding.global.jwt.LoginFilter.COOKIE_EXPIRATION_TIME;

@RestController
public class AuthController {

    private final AuthService authService;

    public AuthController(final AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        String newAccessToken, newRefreshToken;

        try {
            String[] tokens = authService.reissue(request.getCookies());
            newAccessToken = tokens[0];
            newRefreshToken = tokens[1];
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        response.setHeader("access", newAccessToken);
        response.addCookie(createCookie("refresh", newRefreshToken));
        return new ResponseEntity<>(HttpStatus.OK);
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(COOKIE_EXPIRATION_TIME);
        cookie.setHttpOnly(true);

        return cookie;
    }
}
