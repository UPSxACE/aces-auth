package com.upsxace.aces_auth_service.features.apps;

import com.upsxace.aces_auth_service.features.apps.dto.AppDto;
import com.upsxace.aces_auth_service.features.apps.dto.ClientSecretDto;
import com.upsxace.aces_auth_service.features.apps.dto.WriteAppRequest;
import com.upsxace.aces_auth_service.features.user.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
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
        return ResponseEntity.ok(appsService.getAppFromUser(id, userContext.getId()).removeCredentials());
    }

    @PutMapping("/{id}")
    public ResponseEntity<AppDto> updateApp(
            @PathVariable(name = "id") UUID id,
            @Valid @RequestBody WriteAppRequest request
    ){
        return ResponseEntity.ok(appsService.updateAppByUser(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteApp(
            @PathVariable(name = "id") UUID id
    ) {
        appsService.deleteAppByUser(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/reset-secret")
    public ResponseEntity<ClientSecretDto> resetSecret(
            @PathVariable(name = "id") UUID id
    ){
        return ResponseEntity.ok(appsService.resetAppSecretByUser(id));
    }

    @PostMapping("/consent")
    public ResponseEntity<Void> consent(
            @RequestParam(name = "client_id") String clientId,
            @Valid @NotBlank @RequestParam(name = "scopes") String scopes
    ){
        appsService.giveConsentByUser(clientId, scopes);
        return ResponseEntity.ok().build();
    }
}
