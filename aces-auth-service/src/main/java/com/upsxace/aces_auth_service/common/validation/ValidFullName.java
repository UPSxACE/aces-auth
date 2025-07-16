package com.upsxace.aces_auth_service.common.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = FullNameValidator.class)
@Target({ ElementType.FIELD, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidFullName {
    String message() default "Invalid full name format.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}