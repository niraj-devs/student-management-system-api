package com.niraj.education.user.controller;

import com.niraj.education.user.dto.LoginRequest;
import com.niraj.education.user.dto.UserResponse;
import com.niraj.education.user.entity.RefreshToken;
import com.niraj.education.user.entity.User;
import com.niraj.education.user.exception.RefreshTokenException;
import com.niraj.education.user.repository.UserRepository;
import com.niraj.education.user.service.RefreshTokenService;
import com.niraj.education.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import com.niraj.education.user.security.JWTService;
import com.niraj.education.user.repository.RefreshTokenRepository;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@RequestBody User user) {

        User registeredUser = userService.register(user);

        UserResponse response = new UserResponse(
                "User registered successfully",
                registeredUser.getUsername(),
                registeredUser.getRole()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<?> Login(@RequestBody LoginRequest request) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        String accessToken = jwtService.generateToken(
                authentication.getName()
        );

        User user = userRepository.findByUsername(
                authentication.getName()
        ).orElseThrow();

        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(user);

        return ResponseEntity.ok(
                Map.of(
                        "accessToken", accessToken,
                        "refreshToken", refreshToken.getToken()
                )
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(
            @RequestParam String refreshToken) {

        RefreshToken token = refreshTokenRepository
                .findByToken(refreshToken)
                .orElseThrow(() ->
                        new RefreshTokenException("Refresh token not found"));

        refreshTokenService.verifyExpiration(token);

        User user=token.getUser();

        refreshTokenRepository.delete(token);

        String accessToken = jwtService.generateToken(
                user.getUsername()
        );

        RefreshToken newRefreshToken= refreshTokenService.createRefreshToken(user);

        return ResponseEntity.ok(
                Map.of(
                        "accessToken", accessToken,
                        "refreshToken", newRefreshToken.getToken()
                )
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestParam String refreshToken
    ){
        RefreshToken token=refreshTokenRepository
                .findByToken(refreshToken)
                .orElseThrow(()->
                        new RefreshTokenException("Refresh token not found"));
        refreshTokenRepository.delete(token);

        return ResponseEntity.ok(
                Map.of("message","Logout successfully!")
        );
    }
}
