package com.upsxace.aces_auth_service.features.auth.oauth.strategies;

import com.upsxace.aces_auth_service.features.auth.oauth.OAuth2LoginError;
import com.upsxace.aces_auth_service.features.auth.oauth.OpenIdConnectStrategy;
import com.upsxace.aces_auth_service.features.auth.oauth.OpenIdProfile;
import com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos.DiscordIdTokenResponse;
import com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos.DiscordProfileResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;


import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
@Lazy
public class DiscordOidcStrategy implements OpenIdConnectStrategy {
    @Value("${config.oauth.discord.client-id}")
    private String clientId;

    @Value("${config.oauth.discord.client-secret}")
    private String clientSecret;

    private final RestClient restClient;

    public DiscordOidcStrategy() {
        this.restClient = RestClient.builder().baseUrl("https://discord.com").build();
    }

    @Override
    public String getStrategyName() {
        return "discord";
    }

    @Override
    public String getToken(String code, String codeVerifier, String redirectUri) {
        try {
            String auth = clientId + ":" + clientSecret;
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
            String authHeader = "Basic " + encodedAuth;

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "authorization_code");
            body.add("code", code);
            body.add("code_verifier", codeVerifier);
            body.add("redirect_uri", redirectUri);

            var result = this.restClient.post().uri("/api/oauth2/token")
                    .header(HttpHeaders.AUTHORIZATION, authHeader)
                    .body(body)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .retrieve()
                    .body(DiscordIdTokenResponse.class);

            if (
                    result == null
                            || !result.getScope().contains("email")
                            || !result.getScope().contains("openid")
                            || !result.getScope().contains("identify")
            ) {
                throw new OAuth2LoginError();
            }

            return result.getAccess_token();
        } catch (Exception ex) {
            throw new OAuth2LoginError();
        }
    }

    @Override
    public OpenIdProfile getOpenIdProfile(String tokenString) {
        String authHeader = "Bearer " + tokenString;

        try {
            var profileResult = this.restClient
                    .get()
                    .uri("/api/users/@me")
                    .header(HttpHeaders.AUTHORIZATION, authHeader)
                    .retrieve().body(DiscordProfileResponse.class);

            if (profileResult == null) {
                throw new OAuth2LoginError();
            }

            var userId = profileResult.getId();
            var email = profileResult.getEmail();

            if (userId == null || email == null) {
                throw new OAuth2LoginError();
            }

            return new OpenIdProfile(userId, email);
        } catch (Exception ex) {
            throw new OAuth2LoginError();
        }
    }
}
