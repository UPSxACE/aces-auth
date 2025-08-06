package com.upsxace.aces_auth_service.features.apps;

import com.upsxace.aces_auth_service.config.error.NotFoundException;
import com.upsxace.aces_auth_service.features.apps.utils.AesKeyGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@RequiredArgsConstructor
public class AppOAuthClientAuthenticationProvider implements AuthenticationProvider {
    private final AesKeyGenerator aesKeyGenerator;
    private final RegisteredClientRepository clientRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var username = authentication.getName(); // client id
        var pwd = authentication.getCredentials().toString(); // client secret
        var app = clientRepository.findByClientId(username);

        if (app == null)
            throw new NotFoundException("App not found.");

        if (app.getClientSecret() == null)
            throw new IllegalStateException("App client secret should not be null.");

        try {
            if (!pwd.equals(aesKeyGenerator.decryptClientSecret(app.getClientSecret()))) {
                throw new BadCredentialsException("Invalid client secret.");
            }
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid client secret.");
        }

        return new OAuth2ClientAuthenticationToken(
                app,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                pwd
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
