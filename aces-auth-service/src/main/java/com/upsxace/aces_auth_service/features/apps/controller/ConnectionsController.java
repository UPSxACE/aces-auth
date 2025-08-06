package com.upsxace.aces_auth_service.features.apps.controller;

import com.upsxace.aces_auth_service.features.apps.dto.ConnectionDto;
import com.upsxace.aces_auth_service.features.apps.service.AppsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/apps/connections")
@RequiredArgsConstructor
public class ConnectionsController {
    private final AppsService appsService;

    @GetMapping
    public ResponseEntity<List<ConnectionDto>> getConnections() {
        var connections = appsService.getConnectionsByUser();
        return ResponseEntity.ok(connections);
    }

    @DeleteMapping
    public ResponseEntity<Void> disconnectApp(
            @RequestParam(name = "client_id") String clientId
    ) {
        appsService.disconnectAppByUser(clientId);
        return ResponseEntity.noContent().build();
    }
}
