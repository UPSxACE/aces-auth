package com.upsxace.aces_auth_service.features.auth.oauth.strategies;

import com.upsxace.aces_auth_service.features.auth.oauth.OAuth2LoginError;
import com.upsxace.aces_auth_service.features.auth.oauth.OpenIdConnectStrategy;
import com.upsxace.aces_auth_service.features.auth.oauth.OpenIdProfile;
import com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos.GithubIdTokenResponse;
import com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos.GithubEmailDto;
import com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos.GithubProfileResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Component
@Lazy
public class GithubOidcStrategy implements OpenIdConnectStrategy {
    @Value("${config.oauth.github.client-id}")
    private String clientId;

    @Value("${config.oauth.github.client-secret}")
    private String clientSecret;

    private final RestClient restClient;
    private final RestClient apiRestClient;

    public GithubOidcStrategy() {
        this.restClient = RestClient.builder().baseUrl("https://github.com").build();
        this.apiRestClient = RestClient.builder().baseUrl("https://api.github.com").build();
    }

    @Override
    public String getStrategyName() {
        return "github";
    }

    @Override
    public String getToken(String code, String codeVerifier, String redirectUri) {
        try {
            var result = this.restClient.post().uri("/login/oauth/access_token").body(Map.of(
                            "client_id", clientId,
                            "client_secret", clientSecret,
                            "redirect_uri", redirectUri,
                            "code", code,
                            "code_verifier", codeVerifier
                    )).accept(MediaType.APPLICATION_JSON).contentType(MediaType.APPLICATION_JSON)
                    .retrieve().body(GithubIdTokenResponse.class);

            if (result == null || !result.getScope().contains("read:user") || !result.getScope().contains("user:email")) {
                throw new OAuth2LoginError();
            }

            return result.getAccess_token();
        } catch (Exception ex) {
            throw new OAuth2LoginError();
        }
    }

    @Override
    public OpenIdProfile getOpenIdProfile(String tokenString) {
        try {
            var profileResult = this.apiRestClient.get().uri("/user")
                    .accept(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + tokenString)
                    .retrieve().body(GithubProfileResponse.class);

            if (profileResult == null) {
                throw new OAuth2LoginError();
            }

            var id = profileResult.getId();

            var emailResult = this.apiRestClient.get().uri("/user/emails")
                    .accept(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + tokenString)
                    .retrieve()
                    .body(new ParameterizedTypeReference<List<GithubEmailDto>>() {
                    });

            if (id == 0 || emailResult == null) {
                throw new OAuth2LoginError();
            }

            var email = emailResult
                    .stream()
                    .filter(GithubEmailDto::isPrimary)
                    .findFirst()
                    .orElseThrow(OAuth2LoginError::new)
                    .getEmail();

            return new OpenIdProfile(String.valueOf(id), email);
        } catch (Exception ex) {
            throw new OAuth2LoginError();
        }
    }
}
