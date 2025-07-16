package com.upsxace.aces_auth_service.common.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class UsernameValidator implements ConstraintValidator<ValidUsername, String> {

    private static final String REGEX = "^[a-zA-Z](?!.*[_.]{2})[a-zA-Z0-9._]{2,29}$";

    @Override
    public boolean isValid(String username, ConstraintValidatorContext context) {
        if (username == null) return false;
        if (!username.matches(REGEX)) return false;
        char lastChar = username.charAt(username.length() - 1);
        return lastChar != '.' && lastChar != '_';
    }
}