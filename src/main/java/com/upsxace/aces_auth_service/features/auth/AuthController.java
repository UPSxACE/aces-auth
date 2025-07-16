package com.upsxace.aces_auth_service.features.auth;

import com.upsxace.aces_auth_service.features.auth.dtos.RegisterByEmailRequest;
import com.upsxace.aces_auth_service.features.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(
            @Valid @RequestBody RegisterByEmailRequest registerByEmailRequest
    ){
        userService.registerByEmail(registerByEmailRequest);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
