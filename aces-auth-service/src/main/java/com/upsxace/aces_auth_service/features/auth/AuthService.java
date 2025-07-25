package com.upsxace.aces_auth_service.features.auth;

import com.upsxace.aces_auth_service.config.error.BadRequestException;
import com.upsxace.aces_auth_service.config.error.NotFoundException;
import com.upsxace.aces_auth_service.features.auth.dto.LoginRequest;
import com.upsxace.aces_auth_service.features.auth.dto.OAuthLoginRequest;
import com.upsxace.aces_auth_service.features.auth.dto.RefreshTokensResult;
import com.upsxace.aces_auth_service.features.auth.dto.TokenGenerationResult;
import com.upsxace.aces_auth_service.features.auth.jwt.*;
import com.upsxace.aces_auth_service.features.auth.oauth.OpenIdConnectContext;
import com.upsxace.aces_auth_service.features.user.User;
import com.upsxace.aces_auth_service.features.user.UserRepository;
import com.upsxace.aces_auth_service.features.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenSessionManager tokenSessionManager;
    private final OpenIdConnectContext openIdConnectContext;
    private final UserAuthProviderRepository userAuthProviderRepository;
    private final UserService userService;

    private TokenGenerationResult generateToken(User user, List<String> amr){
        var refreshToken = tokenSessionManager.createTokenSession(user.getId(), amr);
        var accessToken = tokenSessionManager.getAccessToken(refreshToken);

        return new TokenGenerationResult(accessToken, refreshToken);
    }

    public TokenGenerationResult loginByCredentials(LoginRequest request) {
        var user = userRepository.findByUsernameOrEmail(request.getIdentifier(), request.getIdentifier())
                .orElseThrow(() -> new NotFoundException("User not found with identifier: " + request.getIdentifier()));

        if(user.getPassword() == null){
            throw new BadCredentialsException("Bad credentials.");
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getId(),
                        request.getPassword()
                )
        );

        return generateToken(user, Collections.singletonList("pwd"));
    }

    public TokenGenerationResult loginByOAuth(String provider, OAuthLoginRequest request) {
        var openIdProfile = this.openIdConnectContext.authenticate(
                provider,
                request.getCode(),
                request.getCodeVerifier(),
                request.getRedirectUri()
        );

        // if oidc is already registered, simply login and ignore email (email is just for registration purposes)
        var existingUserAuthProvider = userAuthProviderRepository.findByProviderNameAndProviderUserOid(provider, openIdProfile.getId()).orElse(null);
        if(existingUserAuthProvider != null){
            return generateToken(existingUserAuthProvider.getUser(), List.of("oauth", provider));
        }

        var emailRegistered = userRepository.existsByEmail(openIdProfile.getEmail());
        if(emailRegistered){
            // email cannot be registered already
            throw new BadRequestException("An account with this email already exists and is linked to a different login method. Please sign in using your original provider(or password) or contact support if you need help accessing your account.");
        }

        // since both oidc and email are unregistered, create new user
        var newUser = userService.registerByOidc(openIdProfile.getEmail(), provider, openIdProfile.getId());

        return generateToken(newUser.getUser(), List.of("oauth", provider));
    }

    public RefreshTokensResult refreshTokens(String refreshToken) {
        return tokenSessionManager.refreshToken(refreshToken);
    }

    public void revokeTokenSession(String refreshToken) {
        tokenSessionManager.revokeTokenSession(refreshToken);
    }

    public TokenSessionInfoDto getSessionInfo(String refreshToken){
       return tokenSessionManager.getSessionInfo(refreshToken);
    }
}
