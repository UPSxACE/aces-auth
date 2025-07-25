package com.upsxace.aces_auth_service.features.apps;

import com.upsxace.aces_auth_service.config.error.NotFoundException;
import com.upsxace.aces_auth_service.features.apps.dto.AppDto;
import com.upsxace.aces_auth_service.features.apps.dto.WriteAppRequest;
import com.upsxace.aces_auth_service.features.user.Role;
import com.upsxace.aces_auth_service.features.user.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AppsService {
    private final UserService userService;
    private final AppRepository appRepository;
    private final AesKeyGenerator aesKeyGenerator;
    private final AppMapper appMapper;

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    private String generateClientId() {
        String clientId;
        do {
            byte[] randomBytes = new byte[24];
            secureRandom.nextBytes(randomBytes);
            clientId = base64Encoder.encodeToString(randomBytes);
        } while (appRepository.existsByClientId(clientId));
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

            appRepository.save(newApp);

            var appDto = appMapper.toDto(newApp);
            appDto.setClientSecret(clientSecret);

            return appDto;
        } catch (Exception ex) {
            throw new InternalError("Failed creating app");
        }
    }

    public AppDto getAppByUser(UUID appId, UUID userId) {
        return appMapper.toDto(
                appRepository.findByIdAndOwnerIdAndDeletedAtIsNull(appId, userId).orElseThrow(
                        NotFoundException::new
                )
        );
    }

    public List<AppDto> getAppsFromUser(UUID uuid) {
        return appMapper.toDtoList(appRepository.findByOwnerIdAndDeletedAtIsNull(uuid));
    }

    public List<AppDto> removeCredentials(List<AppDto> appDtos) {
        appDtos.forEach(AppDto::removeCredentials);
        return appDtos;
    }

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
}
