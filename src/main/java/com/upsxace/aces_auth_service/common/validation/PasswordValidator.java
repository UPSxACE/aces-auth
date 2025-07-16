package com.upsxace.aces_auth_service.common.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordValidator implements ConstraintValidator<ValidPassword, String> {

    private static final String LOWERCASE_PATTERN = ".*[a-z].*";
    private static final String UPPERCASE_PATTERN = ".*[A-Z].*";
    private static final String DIGIT_PATTERN = ".*\\d.*";

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) return false;

        if (password.length() < 9) return false;
        if (!password.matches(LOWERCASE_PATTERN)) return false;
        if (!password.matches(UPPERCASE_PATTERN)) return false;
        return password.matches(DIGIT_PATTERN);
    }
}