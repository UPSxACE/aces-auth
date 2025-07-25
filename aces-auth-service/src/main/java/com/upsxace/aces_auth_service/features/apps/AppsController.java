package com.upsxace.aces_auth_service.features.apps;

import com.upsxace.aces_auth_service.features.apps.dto.AppDto;
import com.upsxace.aces_auth_service.features.apps.dto.WriteAppRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/apps")
@RequiredArgsConstructor
public class AppsController {
    private final AppsService appsService;

    @PostMapping
    public ResponseEntity<AppDto> createApp(
            @Valid @RequestBody WriteAppRequest request,
            UriComponentsBuilder uriBuilder
    ) {
        var appDto = appsService.createApp(request);
        var uri = uriBuilder
                .path("/apps/{id}")
                .buildAndExpand(appDto.getId())
                .toUri();

        return ResponseEntity.created(uri).body(appDto);
    }
}
