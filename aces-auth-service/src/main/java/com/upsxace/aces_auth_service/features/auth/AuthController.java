package com.upsxace.aces_auth_service.features.auth;

import com.upsxace.aces_auth_service.features.auth.dtos.LoginRequest;
import com.upsxace.aces_auth_service.features.auth.dtos.JwtDto;
import com.upsxace.aces_auth_service.features.auth.dtos.RegisterByEmailRequest;
import com.upsxace.aces_auth_service.features.auth.jwt.JwtService;
import com.upsxace.aces_auth_service.features.user.UserService;
import com.upsxace.aces_auth_service.features.user.dtos.UserProfileDto;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;
    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(
            @Valid @RequestBody RegisterByEmailRequest request
    ){
        userService.registerByEmail(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public ResponseEntity<JwtDto> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response
    ){
        var loginResult = authService.loginByCredentials(request);

        var cookie = jwtService.createRefreshTokenCookie(loginResult.getRefreshToken());
        response.addCookie(cookie);

        return ResponseEntity
                .ok()
                .header("Authorization", "Bearer " + loginResult.getAccessToken())
                .body(new JwtDto(loginResult.getAccessToken()));
    }

    @GetMapping("/me")
    public ResponseEntity<UserProfileDto> me(){
        var userContext = userService.getUserContext();
        if(userContext == null) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok().body(userService.fetchUserProfile(userContext.getId()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtDto> refresh(
            @RequestHeader(name = "Authorization") String authorizationHeader,
            @CookieValue(name = "refreshToken") String refreshToken,
            HttpServletResponse response
    ){
        if(authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new BadCredentialsException("Invalid authorization header");
        }

        var accessToken = authorizationHeader.replace("Bearer ", "");

        var refreshTokenResult = jwtService.refreshToken(accessToken, refreshToken);
        if(!refreshTokenResult.getRefreshToken().equals(refreshToken)){
            var cookie = jwtService.createRefreshTokenCookie(refreshTokenResult.getRefreshToken());
            response.addCookie(cookie);
        }

        return ResponseEntity.ok().body(new JwtDto(refreshTokenResult.getAccessToken()));
    }
}
