package com.upsxace.aces_auth_service.features.apps.mapper;

import com.upsxace.aces_auth_service.features.apps.dto.ConnectionAppDto;
import com.upsxace.aces_auth_service.features.apps.entity.App;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface ConnectionAppMapper {
    ConnectionAppDto toDto(App connectionApp);
}
