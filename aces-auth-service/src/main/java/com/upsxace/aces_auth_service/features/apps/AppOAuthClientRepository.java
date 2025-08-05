package com.upsxace.aces_auth_service.features.apps;

import com.upsxace.aces_auth_service.config.AppConfig;
import com.upsxace.aces_auth_service.config.error.NotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@RequiredArgsConstructor
public class AppOAuthClientRepository implements RegisteredClientRepository {
    private final AppRepository appRepository;
    private final AppConfig appConfig;

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new IllegalStateException("Do not manually register clients.");
    }

    private RegisteredClient appToRegisteredClient(App app){
        return RegisteredClient.withId(app.getId().toString())
                .clientId(app.getClientId())
                .clientSecret(app.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUris((set)->{
                    var uris = AppMapper.toStringList(app.getRedirectUris());
                    set.add(appConfig.getFrontendUrl() + "/oauth2/demo/callback");
                    set.addAll(uris);
                })
                .postLogoutRedirectUri(app.getRedirectUris())
                // FIXME: customize the jwt it returns, and the refresh token?
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        // FIXME: customize token generator?
    }

    @Override
    public RegisteredClient findById(String id) {
        var app = appRepository.findByIdAndDeletedAtIsNull(UUID.fromString(id)).orElseThrow(()->new NotFoundException("App not found."));
        return appToRegisteredClient(app);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        var app = appRepository.findByClientIdAndDeletedAtIsNull(clientId).orElseThrow(()->new NotFoundException("App not found."));
        return appToRegisteredClient(app);
    }
}
