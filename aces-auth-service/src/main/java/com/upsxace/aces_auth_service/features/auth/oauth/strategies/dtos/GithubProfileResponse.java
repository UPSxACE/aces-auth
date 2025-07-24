package com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos;

import lombok.Data;

@Data
public class GithubProfileResponse {
    private final int id;
    private final String login;
    private final String avatar_url;
    private final String name;
}
