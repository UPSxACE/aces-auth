package com.upsxace.aces_auth_service.features.info;

import com.upsxace.aces_auth_service.features.apps.AppsService;
import com.upsxace.aces_auth_service.features.apps.dto.PublicAppInfoDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequestMapping("/info")
@RequiredArgsConstructor
public class InfoController {
    private final AppsService appsService;

    @GetMapping("/app")
    public ResponseEntity<PublicAppInfoDto> getAppInfo(
            @Valid @NotBlank @RequestParam(name = "client_id") String clientId,
            @Valid @Size(min = 1) @RequestParam(name = "check_scopes", required = false) String checkScopes
    ){
        if(checkScopes != null){
            var scopesList = Set.of(checkScopes.split(" "));
            return ResponseEntity.ok(appsService.getPublicAppInfo(clientId, scopesList));
        }
        return ResponseEntity.ok(appsService.getPublicAppInfo(clientId));
    }
}
