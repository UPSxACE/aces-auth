package com.upsxace.aces_auth_service.features.auth.jwt;

import com.upsxace.aces_auth_service.config.AppConfig;
import com.upsxace.aces_auth_service.features.auth.dtos.RefreshTokenResult;
import com.upsxace.aces_auth_service.features.user.User;
import com.upsxace.aces_auth_service.features.user.UserContext;
import com.upsxace.aces_auth_service.features.user.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final AppConfig appConfig;
    private final UserRepository userRepository;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(appConfig.getJwt().getSecret().getBytes(StandardCharsets.UTF_8));
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateTokenForUser(User user, AuthenticationMethodReference amr) {
        final long TOKEN_EXPIRATION_MS = appConfig.getJwt().getAccessTokenExpiration() * 1000;

        return Jwts.builder()
                .subject(user.getId().toString())
                .issuer("aces-auth-service")
                .claim("token_type", "access")
                .claim("authorities", "ROLE_" + user.getRole())
                .claim("amr", Collections.singletonList(amr.name().toLowerCase()))
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + TOKEN_EXPIRATION_MS))
                .signWith(getSigningKey())
                .compact();
    }

    public String generateRefreshToken(String subject) {
        final long TOKEN_EXPIRATION_MS = appConfig.getJwt().getRefreshTokenExpiration() * 1000;

        return Jwts.builder()
                .subject(subject)
                .issuer("aces-auth-service")
                .claim("token_type", "refresh")
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + TOKEN_EXPIRATION_MS))
                .signWith(getSigningKey())
                .compact();
    }

    public Cookie createRefreshTokenCookie(String refreshToken) {
        var cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true); // prevent JavaScript access
        cookie.setPath("/auth/refresh"); // only send cookie to this route
        cookie.setMaxAge((int) appConfig.getJwt().getRefreshTokenExpiration());
        cookie.setSecure(true); // only https connections

        return cookie;
    }

    public Optional<Claims> resolveToken(String token, TokenType tokenType) {
        try {
            var claims = getClaims(token);

            var tokenTypeMismatch = !tokenType.name().toLowerCase().equals(claims.get("token_type", String.class));
            var expired = new Date().after(claims.getExpiration());

            if (tokenTypeMismatch || expired) {
                return Optional.empty();
            }

            return Optional.of(claims);
        } catch (JwtException ex) {
            return Optional.empty();
        }
    }

    private boolean shouldRenewToken(Date expiration, long lifetimeInSeconds) {
        long threshold = lifetimeInSeconds * 1000 * 2 / 3;
        Date renewalDate = new Date(expiration.getTime() - threshold);
        return new Date().after(renewalDate);
    }

    public RefreshTokenResult refreshToken(String accessToken, String refreshToken) {
            var refreshTokenClaims = resolveToken(refreshToken, TokenType.REFRESH)
                    .orElseThrow(() -> new BadCredentialsException("Invalid refresh token."));
            var accessTokenClaims = resolveToken(accessToken, TokenType.ACCESS)
                    .orElseThrow(() -> new BadCredentialsException("Invalid access token."));

            if (!refreshTokenClaims.getSubject().equals(accessTokenClaims.getSubject())) {
                throw new BadCredentialsException("Refresh token does not match access token.");
            }

            var freshAccessToken = accessToken;
            var freshRefreshToken = refreshToken;

            // Refresh only if access token is older than 2/3 of its lifetime
            if (shouldRenewToken(accessTokenClaims.getExpiration(), appConfig.getJwt().getAccessTokenExpiration())) {
                var amr = AuthenticationMethodReference.valueOf(
                        accessTokenClaims
                                .get("amr", List.class)
                                .getFirst()
                                .toString()
                                .toUpperCase()
                );

                var userId = UUID.fromString(accessTokenClaims.getSubject());
                var user = userRepository.findById(userId).orElseThrow(() -> new BadCredentialsException("Could not refresh token, user not found."));

                freshAccessToken = generateTokenForUser(user, amr);
            }

            // Refresh only if refresh token is older than 2/3 of its lifetime
            if (shouldRenewToken(refreshTokenClaims.getExpiration(), appConfig.getJwt().getRefreshTokenExpiration())) {
                freshRefreshToken = generateRefreshToken(accessTokenClaims.getSubject());
            }

            return new RefreshTokenResult(freshAccessToken, freshRefreshToken);

    }

    public UserContext createUserContextFromToken(String token) {
        var claims = getClaims(token);
        var id = claims.getSubject();
        var authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(claims.get("authorities", String.class));
        return new UserContext(UUID.fromString(id), authorities);
    }
}
