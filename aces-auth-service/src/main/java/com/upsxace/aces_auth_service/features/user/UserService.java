package com.upsxace.aces_auth_service.features.user;

import com.upsxace.aces_auth_service.config.error.BadRequestException;
import com.upsxace.aces_auth_service.config.error.NotFoundException;
import com.upsxace.aces_auth_service.features.auth.UserAuthProvider;
import com.upsxace.aces_auth_service.features.auth.UserAuthProviderRepository;
import com.upsxace.aces_auth_service.features.auth.dto.RegisterByEmailRequest;
import com.upsxace.aces_auth_service.features.user.dto.UserProfileDto;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final UserAuthProviderRepository userAuthProviderRepository;

    private com.upsxace.aces_auth_service.features.user.User setUserDefaults(com.upsxace.aces_auth_service.features.user.User user) {
        user.setRole(Role.USER);
        return user;
    }

    public com.upsxace.aces_auth_service.features.user.User getUserById(UUID uuid){
        return userRepository.findById(uuid)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public com.upsxace.aces_auth_service.features.user.User getUserById(String uuid){
        return userRepository.findById(UUID.fromString(uuid))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Override
    public UserDetails loadUserByUsername(String uuid) {
        var user = getUserById(uuid);

        return new User(
                user.getId().toString(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );
    }

    public List<String> getUserAuthorities(UUID userId) {
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found"));

        return List.of("ROLE_" + user.getRole().name());
    }

    public UserContext getUserContext() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }

        return (UserContext) authentication.getPrincipal();
    }

    @Transactional
    public void registerByEmail(RegisterByEmailRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email already taken.");
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BadRequestException("Username already taken.");
        }

        var user = userMapper.fromRequestToEntity(request);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        setUserDefaults(user);
        userRepository.save(user);
    }

    private String generateUsernameFromEmail(String email) {
        var localPart = email.substring(0, email.indexOf("@"));
        var usernameHead = localPart.length() <= 5 ? localPart : localPart.substring(0, 5);

        Random random = new Random();
        int number = random.nextInt(10000) + 1;
        while(userRepository.existsByUsername(usernameHead + number)){
            number++;
        }

        return usernameHead+number;
    }

    @Transactional
    public UserAuthProvider registerByOidc(String userEmail, String providerName, String providerOidc) {
        if (userRepository.existsByEmail(userEmail)) {
            throw new BadRequestException("Email already taken.");
        }

        var username = generateUsernameFromEmail(userEmail);
        var user = com.upsxace.aces_auth_service.features.user.User.builder()
                .username(username)
                .email(userEmail)
                .build();
        setUserDefaults(user);
        userRepository.save(user);

        var authProvider = UserAuthProvider.builder()
                .providerName(providerName)
                .providerUserOid(providerOidc)
                .user(user)
                .build();
        userAuthProviderRepository.save(authProvider);

        return authProvider;
    }

    public UserProfileDto fetchUserProfile(UUID userId) {
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found"));

        return userMapper.toProfileDto(user);
    }
}
