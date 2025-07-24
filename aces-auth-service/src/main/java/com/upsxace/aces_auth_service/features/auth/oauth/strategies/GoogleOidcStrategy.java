package com.upsxace.aces_auth_service.features.auth.oauth.strategies;

import com.upsxace.aces_auth_service.features.auth.oauth.OAuth2LoginError;
import com.upsxace.aces_auth_service.features.auth.oauth.OpenIdConnectStrategy;
import com.upsxace.aces_auth_service.features.auth.oauth.OpenIdProfile;
import com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos.GoogleIdTokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Component
@Lazy
public class GoogleOidcStrategy implements OpenIdConnectStrategy {
    @Value("${config.oauth.google.client-id}")
    private String clientId;

    @Value("${config.oauth.google.client-secret}")
    private String clientSecret;

    private final RestClient restClient;

    public GoogleOidcStrategy() {
        this.restClient = RestClient.builder().baseUrl("https://oauth2.googleapis.com").build();
    }

    @Override
    public String getStrategyName() {
        return "google";
    }

    @Override
    public String getToken(String code, String codeVerifier, String redirectUri) {
        try {
            var result = this.restClient.post().uri("/token").body(Map.of(
                            "client_id", clientId,
                            "client_secret", clientSecret,
                            "redirect_uri", redirectUri,
                            "code", code,
                            "code_verifier", codeVerifier,
                            "grant_type", "authorization_code"
                    )).accept(MediaType.APPLICATION_JSON).contentType(MediaType.APPLICATION_JSON)
                    .retrieve().body(GoogleIdTokenResponse.class);

            if (result == null || !result.getScope().contains("https://www.googleapis.com/auth/userinfo.email") || !result.getScope().contains("openid")) {
                throw new OAuth2LoginError();
            }

            return result.getId_token();
        } catch (Exception ex) {
            throw new OAuth2LoginError();
        }
    }

    @Override
    public OpenIdProfile getOpenIdProfile(String tokenString) {
        var decoder = NimbusJwtDecoder.withJwkSetUri("https://www.googleapis.com/oauth2/v3/certs").build();

        try {
            var token = decoder.decode(tokenString);

            var claims = token.getClaims();
            var userId = (String) claims.get("sub");
            var email = (String) claims.get("email");

            if (userId == null || email == null) {
                throw new OAuth2LoginError();
            }

            return new OpenIdProfile(userId, email);
        } catch (Exception ex) {
            throw new OAuth2LoginError();
        }
    }
}
