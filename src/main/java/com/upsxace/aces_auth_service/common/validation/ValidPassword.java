package com.upsxace.aces_auth_service.common.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PasswordValidator.class)
@Target({ ElementType.FIELD, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPassword {
    String message() default "Password must contain at least one lowercase letter, one uppercase letter, and one digit.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}