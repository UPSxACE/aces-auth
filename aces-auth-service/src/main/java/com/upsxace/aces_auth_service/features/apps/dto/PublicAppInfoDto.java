package com.upsxace.aces_auth_service.features.apps.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
public class PublicAppInfoDto {
    private final String name;
    private final String clientId;
    private final String homepageUrl;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final Boolean authorized;
}
