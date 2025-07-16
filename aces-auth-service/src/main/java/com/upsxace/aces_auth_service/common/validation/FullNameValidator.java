package com.upsxace.aces_auth_service.common.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class FullNameValidator implements ConstraintValidator<ValidFullName, String> {
    // Unicode-aware regex for letters, spaces, hyphens, and apostrophes
    private static final String REGEX = "^(?!.*[\\s'-]{2})(?!.*[\\s'-]$)(?!^[\\s'-]).*\\p{L}[\\p{L}\\s'-]*$";

    @Override
    public boolean isValid(String fullName, ConstraintValidatorContext context) {
        if (fullName == null) return false;
        return fullName.matches(REGEX);
    }
}