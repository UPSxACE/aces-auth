package com.upsxace.aces_auth_service.features.apps;

import com.upsxace.aces_auth_service.features.apps.dto.AppDto;
import com.upsxace.aces_auth_service.features.apps.dto.WriteAppRequest;
import com.upsxace.aces_auth_service.features.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/apps")
@RequiredArgsConstructor
public class AppsController {
    private final UserService userService;
    private final AppsService appsService;

    @GetMapping
    public ResponseEntity<List<AppDto>> getApps() {
        var userContext = userService.getUserContext();
        return ResponseEntity.ok(appsService.removeCredentials(appsService.getAppsFromUser(userContext.getId())));
    }

    @GetMapping("/{id}")
    public ResponseEntity<AppDto> getApp(
            @PathVariable(name = "id") UUID id
    ) {
        var userContext = userService.getUserContext();
        return ResponseEntity.ok(appsService.getAppByUser(id, userContext.getId()).removeCredentials());
    }

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

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteApp(
            @PathVariable(name = "id") UUID id
    ) {
        appsService.deleteAppByUser(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{id}")
    public ResponseEntity<AppDto> updateApp(
            @PathVariable(name = "id") UUID id,
            @Valid @RequestBody WriteAppRequest request
    ){
        return ResponseEntity.ok(appsService.updateAppByUser(id, request));
    }
}
