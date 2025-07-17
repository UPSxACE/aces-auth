package com.upsxace.aces_auth_service.features.user;

import com.upsxace.aces_auth_service.config.error.BadRequestException;
import com.upsxace.aces_auth_service.config.error.NotFoundException;
import com.upsxace.aces_auth_service.features.auth.dtos.RegisterByEmailRequest;
import com.upsxace.aces_auth_service.features.user.dtos.UserProfileDto;
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

import java.util.Collections;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String uuid) {
        var user = userRepository.findById(UUID.fromString(uuid))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new User(
                user.getId().toString(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );
    }

    public UserContext getUserContext(){
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication instanceof AnonymousAuthenticationToken){
            return null;
        }

        return (UserContext) authentication.getPrincipal();
    }

    @Transactional
    public void registerByEmail(RegisterByEmailRequest request){
        if(userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email already taken.");
        }
        if(userRepository.existsByUsername(request.getUsername())) {
            throw new BadRequestException("Username already taken.");
        }

        var user = userMapper.fromRequestToEntity(request);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);
        userRepository.save(user);
    }

    public UserProfileDto fetchUserProfile(UUID userId) {
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found"));

        return userMapper.toProfileDto(user);
    }
}
