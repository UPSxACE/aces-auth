package com.upsxace.aces_auth_service.features.user;

import com.upsxace.aces_auth_service.features.auth.dtos.RegisterByEmailRequest;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    User fromRequestToEntity(RegisterByEmailRequest request);
}
