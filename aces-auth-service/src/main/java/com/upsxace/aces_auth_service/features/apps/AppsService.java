package com.upsxace.aces_auth_service.features.apps;

import com.upsxace.aces_auth_service.config.error.NotFoundException;
import com.upsxace.aces_auth_service.features.apps.dto.AppDto;
import com.upsxace.aces_auth_service.features.apps.dto.ClientSecretDto;
import com.upsxace.aces_auth_service.features.apps.dto.PublicAppInfoDto;
import com.upsxace.aces_auth_service.features.apps.dto.WriteAppRequest;
import com.upsxace.aces_auth_service.features.user.Role;
import com.upsxace.aces_auth_service.features.user.UserRepository;
import com.upsxace.aces_auth_service.features.user.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AppsService {
    private final UserService userService;
    private final AppRepository appRepository;
    private final AesKeyGenerator aesKeyGenerator;
    private final AppMapper appMapper;
    private final AppUserRepository appUserRepository;

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    private String generateClientId() {
        String clientId;
        do {
            byte[] randomBytes = new byte[24];
            secureRandom.nextBytes(randomBytes);
            clientId = base64Encoder.encodeToString(randomBytes);
        } while (appRepository.existsByClientIdAndDeletedAtIsNull(clientId));
        return clientId;
    }

    private String generateClientSecret() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }

    @Transactional
    public AppDto createApp(WriteAppRequest request) {
        try {
            var user = userService.getUserById(userService.getUserContext().getId());

            var clientSecret = generateClientSecret();

            var newApp = App.builder()
                    .owner(user)
                    .clientId(generateClientId())
                    .clientSecret(aesKeyGenerator.encryptClientSecret(clientSecret))
                    .name(request.getName())
                    .homepageUrl(request.getHomepageUrl())
                    .redirectUris(AppMapper.toListString(request.getRedirectUris()))
                    .build();

            appRepository.saveAndFlush(newApp);

            var appDto = appMapper.toDto(newApp);
            appDto.setClientSecret(clientSecret);

            return appDto;
        } catch (Exception ex) {
            throw new InternalError("Failed creating app");
        }
    }

    public AppDto getAppFromUser(UUID appId, UUID userId) {
        return appMapper.toDto(
                appRepository.findByIdAndOwnerIdAndDeletedAtIsNull(appId, userId).orElseThrow(
                        NotFoundException::new
                )
        );
    }

    public List<AppDto> getAppsFromUser(UUID userId) {
        return appMapper.toDtoList(appRepository.findByOwnerIdAndDeletedAtIsNullOrderByCreatedAtDesc(userId));
    }

    private App getAppByUser(UUID appId){
        var app = appRepository.findByIdAndDeletedAtIsNull(appId).orElseThrow(
                NotFoundException::new
        );

        var userContext = userService.getUserContext();

        if(!app.getOwner().getId().equals(userContext.getId()) && !userContext.hasRole(Role.ADMIN)){
            throw new NotFoundException();
        }

        return app;
    }

    public List<AppDto> removeCredentials(List<AppDto> appDtos) {
        appDtos.forEach(AppDto::removeCredentials);
        return appDtos;
    }

    @Transactional
    public void deleteAppByUser(UUID appId) {
        var app = appRepository.findByIdAndDeletedAtIsNull(appId).orElseThrow(
                NotFoundException::new
        );

        var userContext = userService.getUserContext();

        if(!app.getOwner().getId().equals(userContext.getId()) && !userContext.hasRole(Role.ADMIN)){
            throw new NotFoundException();
        }

        app.setDeletedAt(LocalDateTime.now());
        appRepository.save(app);
    }

    @Transactional
    public AppDto updateAppByUser(UUID appId, WriteAppRequest request) {
        var app = appRepository.findByIdAndDeletedAtIsNull(appId).orElseThrow(
                NotFoundException::new
        );

        var userContext = userService.getUserContext();

        if(!app.getOwner().getId().equals(userContext.getId()) && !userContext.hasRole(Role.ADMIN)){
            throw new NotFoundException();
        }

        appMapper.update(request, app);
        appRepository.save(app);

        return appMapper.toDto(app);
    }

    @Transactional
    public ClientSecretDto resetAppSecretByUser(UUID appId){
        try {
            var app = getAppByUser(appId);
            var newClientSecret = generateClientSecret();

            app.setClientSecret(aesKeyGenerator.encryptClientSecret(newClientSecret));
            appRepository.save(app);

            return new ClientSecretDto(newClientSecret);
        } catch (Exception ex) {
            throw new InternalError("Failed resetting secret.");
        }
    }

    @Transactional
    public void giveConsentByUser(String clientId, String scopes){
        var userContext = userService.getUserContext();

        var appUser = appUserRepository.findByAppClientIdAndUserIdAndAppDeletedAtIsNull(clientId, userContext.getId()).orElseGet(() -> {
            var app = appRepository.findByClientIdAndDeletedAtIsNull(clientId).orElseThrow(() -> new NotFoundException("App not found."));
            var user = userService.getUserById(userContext.getId());
            var newAppUser = new AppUser();
            newAppUser.setApp(app);
            newAppUser.setUser(user);

            return newAppUser;
        });

        appUser.setGrantedAt(LocalDateTime.now());

        var validScopes = Set.of("openid", "profile");
        var requestedScopes = scopes.split(" ");
        var newScopes = new ArrayList<String>();

        for(var scope : requestedScopes){
            if(validScopes.contains(scope))
                newScopes.add(scope);
        }

        appUser.setScopes(String.join(" ", newScopes));

        appUserRepository.save(appUser);
    }

    public boolean checkConsent(String clientId, UUID userId, Set<String> scopes){
        if(!appRepository.existsByClientIdAndDeletedAtIsNull(clientId)){
            throw new NotFoundException("App not found.");
        }

        var appUser = appUserRepository.findByAppClientIdAndUserIdAndAppDeletedAtIsNull(clientId, userId).orElse(null);
        if(appUser == null)
            return false;

        var allowedScopes = appUser.getScopesList();

        for (String scope : scopes){
            if(!allowedScopes.contains(scope))
                return false;
        }

        return true;
    }

    public PublicAppInfoDto getPublicAppInfo(String clientId, Set<String> checkScopes){
            var app = appRepository.findByClientIdAndDeletedAtIsNull(clientId).orElseThrow(() -> new NotFoundException("App not found."));
        var userContext = userService.getUserContext();
        var authorized = userContext != null && !checkScopes.isEmpty()
                ? checkConsent(clientId, userContext.getId(), checkScopes)
                : null;
        return new PublicAppInfoDto(app.getName(), app.getClientId(), app.getHomepageUrl(), authorized);
    }

    public PublicAppInfoDto getPublicAppInfo(String clientId){
        return getPublicAppInfo(clientId, Set.of());
    }
}
