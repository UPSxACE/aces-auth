package com.upsxace.aces_auth_service.features.auth;

import com.upsxace.aces_auth_service.config.AppConfig;
import com.upsxace.aces_auth_service.features.auth.dtos.LoginRequest;
import com.upsxace.aces_auth_service.features.auth.dtos.JwtDto;
import com.upsxace.aces_auth_service.features.auth.dtos.RegisterByEmailRequest;
import com.upsxace.aces_auth_service.features.user.UserService;
import com.upsxace.aces_auth_service.features.user.dtos.UserProfileDto;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AppConfig appConfig;
    private final UserService userService;
    private final AuthService authService;

    private Cookie createRefreshTokenCookie(String refreshToken) {
        var cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true); // prevent JavaScript access
        cookie.setPath("/auth"); // only send cookie to this route
        cookie.setMaxAge((int) appConfig.getJwt().getRefreshTokenExpiration());
        cookie.setSecure(true); // only https connections

        return cookie;
    }

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

        var cookie = createRefreshTokenCookie(loginResult.getRefreshToken());
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
            @CookieValue(name = "refreshToken") String refreshToken,
            HttpServletResponse response
    ){

        var refreshTokenResult = authService.refreshTokens(refreshToken);
        if(!refreshTokenResult.getRefreshToken().equals(refreshToken)){
            var cookie = createRefreshTokenCookie(refreshTokenResult.getRefreshToken());
            response.addCookie(cookie);
        }

        return ResponseEntity.ok().body(new JwtDto(refreshTokenResult.getAccessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = "refreshToken") String refreshToken,
            HttpServletResponse response
    ){
        authService.revokeTokenSession(refreshToken);

        var cookie = createRefreshTokenCookie(refreshToken);
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.noContent().build();
    }
}
