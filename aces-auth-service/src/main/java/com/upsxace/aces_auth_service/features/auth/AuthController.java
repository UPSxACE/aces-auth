package com.upsxace.aces_auth_service.features.auth;

import com.upsxace.aces_auth_service.config.AppConfig;
import com.upsxace.aces_auth_service.features.auth.dto.LoginRequest;
import com.upsxace.aces_auth_service.features.auth.dto.JwtDto;
import com.upsxace.aces_auth_service.features.auth.dto.OAuthLoginRequest;
import com.upsxace.aces_auth_service.features.auth.dto.RegisterByEmailRequest;
import com.upsxace.aces_auth_service.features.auth.jwt.TokenSessionInfoDto;
import com.upsxace.aces_auth_service.features.user.UserService;
import com.upsxace.aces_auth_service.features.user.dto.UserProfileDto;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AppConfig appConfig;
    private final UserService userService;
    private final AuthService authService;

    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refreshToken", refreshToken)
                .domain(appConfig.getCookieDomain())
                .httpOnly(true) // prevent JavaScript access
                .path("/")
                .maxAge(appConfig.getJwt().getRefreshTokenExpiration())
                .secure(true)
                .sameSite("Strict")
                .build();
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
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity
                .ok()
                .header("Authorization", "Bearer " + loginResult.getAccessToken())
                .body(new JwtDto(loginResult.getAccessToken()));
    }

    @PostMapping("/oauth/{provider}")
    public ResponseEntity<JwtDto> oAuthLogin(
            @PathVariable(name = "provider") String provider,
            @RequestBody OAuthLoginRequest request,
            HttpServletResponse response
    ){
        var tokens = authService.loginByOAuth(provider, request);

        var cookie = createRefreshTokenCookie(tokens.getRefreshToken());
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity
                .ok()
                .header("Authorization", "Bearer " + tokens.getAccessToken())
                .body(new JwtDto(tokens.getAccessToken()));
    }

    @GetMapping("/me")
    public ResponseEntity<UserProfileDto> me(){
        var userContext = userService.getUserContext();
        if(userContext == null) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok().body(userService.fetchUserProfile(userContext.getId()));
    }

    @GetMapping("/session")
    public ResponseEntity<TokenSessionInfoDto> getSession(
            @CookieValue(name = "refreshToken", required = false) String refreshToken
    ){
        if(refreshToken == null) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok().body(authService.getSessionInfo(refreshToken));
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtDto> refresh(
            @CookieValue(name = "refreshToken") String refreshToken,
            HttpServletResponse response
    ){
        var refreshTokenResult = authService.refreshTokens(refreshToken);
        if(!refreshTokenResult.getRefreshToken().equals(refreshToken)){
            var cookie = createRefreshTokenCookie(refreshTokenResult.getRefreshToken());
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        }

        return ResponseEntity.ok().body(new JwtDto(refreshTokenResult.getAccessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = "refreshToken", required = false) String refreshToken,
            HttpServletResponse response
    ){
        if(refreshToken != null){
            authService.revokeTokenSession(refreshToken);

            var cookie = createRefreshTokenCookie(refreshToken)
                    .mutate()
                    .maxAge(0)
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        }

        return ResponseEntity.noContent().build();
    }
}
