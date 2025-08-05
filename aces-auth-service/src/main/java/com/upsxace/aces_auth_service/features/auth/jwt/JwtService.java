package com.upsxace.aces_auth_service.features.auth.jwt;

import com.upsxace.aces_auth_service.config.AppConfig;
import com.upsxace.aces_auth_service.config.error.NotFoundException;
import com.upsxace.aces_auth_service.features.user.UserContext;
import com.upsxace.aces_auth_service.features.user.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
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

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateTokenForUser(UUID userId, List<String> amr, List<String> authorities) {
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found"));

        final long TOKEN_EXPIRATION_MS = appConfig.getJwt().getAccessTokenExpiration() * 1000;

        return Jwts.builder()
                .subject(user.getId().toString())
                .issuer("aces-auth-service")
                .claim("token_type", "access")
                .claim("authorities", String.join(",", authorities))
                .claim("amr", amr)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + TOKEN_EXPIRATION_MS))
                .signWith(getSigningKey())
                .compact();
    }

    public Optional<UserContext> createUserContextFromToken(String token) {
        try {
            var claims = getClaims(token);
            var id = claims.getSubject();
            var authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(claims.get("authorities", String.class));
            return Optional.of(new UserContext(UUID.fromString(id), authorities));
        } catch (JwtException ex) {
            return Optional.empty();
        }
    }

    public UserContext createUserContextFromSessionInfo(TokenSessionInfoDto sessionInfo){
        var id = sessionInfo.getUserId();
        var authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",",sessionInfo.getAuthorities()));
        return new UserContext(UUID.fromString(id), authorities);
    }
}
