package com.upsxace.aces_auth_service.features.auth;

import com.upsxace.aces_auth_service.config.error.NotFoundException;
import com.upsxace.aces_auth_service.features.auth.dtos.LoginRequest;
import com.upsxace.aces_auth_service.features.auth.dtos.RefreshTokensResult;
import com.upsxace.aces_auth_service.features.auth.dtos.TokenGenerationResult;
import com.upsxace.aces_auth_service.features.auth.jwt.AuthenticationMethodReference;
import com.upsxace.aces_auth_service.features.auth.jwt.JwtService;
import com.upsxace.aces_auth_service.features.auth.jwt.TokenSessionManager;
import com.upsxace.aces_auth_service.features.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenSessionManager tokenSessionManager;

    public TokenGenerationResult loginByCredentials(LoginRequest request) {
        var user = userRepository.findByUsernameOrEmail(request.getIdentifier(), request.getIdentifier())
                .orElseThrow(() -> new NotFoundException("User not found with identifier: " + request.getIdentifier()));


        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getId(),
                        request.getPassword()
                )
        );

        var refreshToken = tokenSessionManager.createTokenSession(user.getId(), Collections.singletonList(AuthenticationMethodReference.PWD));
        var accessToken = tokenSessionManager.getAccessToken(refreshToken);

        return new TokenGenerationResult(accessToken, refreshToken);
    }

    public RefreshTokensResult refreshTokens(String refreshToken) {
        return tokenSessionManager.refreshToken(refreshToken);
    }

    public void revokeTokenSession(String refreshToken) {
        tokenSessionManager.revokeTokenSession(refreshToken);
    }
}
