package com.upsxace.aces_auth_service.features.user;

import com.upsxace.aces_auth_service.features.auth.dtos.RegisterByEmailRequest;
import com.upsxace.aces_auth_service.features.user.dtos.UserProfileDto;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    User fromRequestToEntity(RegisterByEmailRequest request);
    UserProfileDto toProfileDto(User user);
}
