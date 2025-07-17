package com.upsxace.aces_auth_service.features.auth;

import com.upsxace.aces_auth_service.config.error.NotFoundException;
import com.upsxace.aces_auth_service.features.auth.dtos.LoginRequest;
import com.upsxace.aces_auth_service.features.auth.dtos.TokenGenerationResult;
import com.upsxace.aces_auth_service.features.auth.jwt.AuthenticationMethodReference;
import com.upsxace.aces_auth_service.features.auth.jwt.JwtService;
import com.upsxace.aces_auth_service.features.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public TokenGenerationResult loginByCredentials(LoginRequest request) {
        var user = userRepository.findByUsernameOrEmail(request.getIdentifier(), request.getIdentifier())
                .orElseThrow(() -> new NotFoundException("User not found with identifier: " + request.getIdentifier()));


        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getId(),
                        request.getPassword()
                )
        );

        return jwtService.generateTokenPair(user, AuthenticationMethodReference.PWD);
    }
}
