package com.upsxace.aces_auth_service.features.apps;

import com.upsxace.aces_auth_service.features.apps.dto.AppDto;
import com.upsxace.aces_auth_service.features.apps.dto.WriteAppRequest;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import org.mapstruct.Named;
import org.mapstruct.factory.Mappers;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface AppMapper {
    @Mapping(target = "redirectUris", qualifiedByName = "toStringList")
    AppDto toDto(App app);
    List<AppDto> toDtoList(List<App> apps);
    @Mapping(target = "redirectUris", qualifiedByName = "toListString")
    void update(WriteAppRequest request, @MappingTarget App app);

    @Named("toStringList")
    public static List<String> toStringList(String listString){
        return Arrays.stream(listString.split(",")).collect(Collectors.toList());
    }

    @Named("toListString")
    public static String toListString(List<String> list){
        return String.join(",", list);
    }
}
