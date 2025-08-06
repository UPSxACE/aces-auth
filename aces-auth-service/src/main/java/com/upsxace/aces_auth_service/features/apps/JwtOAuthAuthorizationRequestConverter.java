package com.upsxace.aces_auth_service.features.apps;

import com.upsxace.aces_auth_service.features.apps.service.AppsService;
import com.upsxace.aces_auth_service.features.auth.jwt.JwtService;
import com.upsxace.aces_auth_service.features.auth.jwt.TokenSessionManager;
import com.upsxace.aces_auth_service.features.user.UserContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class JwtOAuthAuthorizationRequestConverter implements AuthenticationConverter {
    private static final OAuth2AuthorizationCodeRequestAuthenticationConverter DELEGATE =
            new OAuth2AuthorizationCodeRequestAuthenticationConverter();

    private final JwtService jwtService;
    private final AppsService appsService;
    private final TokenSessionManager tokenSessionManager;

    public UserContext resolveUserContext(HttpServletRequest request){
        var cookies = request.getCookies();
        var refreshToken = cookies != null
                ? Arrays.stream(cookies).filter(c -> c.getName().equals("refreshToken")).findFirst().orElse(null)
                : null;
        if(refreshToken != null){
            try {
                var sessionInfo = tokenSessionManager.getSessionInfo(refreshToken.getValue());
                return jwtService.createUserContextFromSessionInfo(sessionInfo);
            } catch(Exception ignored) {}
        }

        var authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }

        var token = authHeader.replace("Bearer ", "");

        return jwtService.createUserContextFromToken(token).orElse(null);
    }


    @Override
    public Authentication convert(HttpServletRequest request) {
        var userContext = resolveUserContext(request);
        if (userContext == null) {
            return null;
        }

        var authentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) DELEGATE.convert(request);
        if (authentication == null) {
            return null;
        }

        var principal = new UsernamePasswordAuthenticationToken(
//                userContext, // FIXME: implement OAuth2TokenCustomizer
                userContext.getId().toString(), // until OAuth2TokenCustomizer is implemented, use id as principal
                null,
                userContext.getAuthorities()
        );

        // check consent
        if(!appsService.checkConsent(authentication.getClientId(), userContext.getId(), authentication.getScopes())){
//            throw new ForbiddenRequestException("User has not granted consent to this client."); // FIXME: find out where to catch this
            return null;
        }

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                authentication.getAuthorizationUri(),
                authentication.getClientId(),
                principal,
                authentication.getRedirectUri(),
                authentication.getState(),
                authentication.getScopes(),
                authentication.getAdditionalParameters()
        );
    }
}
