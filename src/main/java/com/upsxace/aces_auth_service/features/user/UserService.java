package com.upsxace.aces_auth_service.features.user;

import com.upsxace.aces_auth_service.config.error.BadRequestException;
import com.upsxace.aces_auth_service.features.auth.dtos.RegisterByEmailRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

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
}
