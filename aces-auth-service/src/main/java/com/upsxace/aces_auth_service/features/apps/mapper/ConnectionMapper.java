package com.upsxace.aces_auth_service.features.apps.mapper;

import com.upsxace.aces_auth_service.features.apps.dto.ConnectionDto;
import com.upsxace.aces_auth_service.features.apps.entity.AppUser;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring", uses = ConnectionAppMapper.class)
public interface ConnectionMapper {
    @Mapping(target = "scopes", qualifiedByName = "toStringList")
    ConnectionDto toDto(AppUser connection);
    List<ConnectionDto> toDtoList(List<AppUser> connections);

    @Named("toStringList")
    public static List<String> toStringList(String listString){
        return Arrays.stream(listString.split(" ")).collect(Collectors.toList());
    }
}
