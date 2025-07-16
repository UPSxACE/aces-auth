package com.upsxace.aces_auth_service.config.error;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@NoArgsConstructor
public class ErrorsDto {
    private final Map<String, String> errors = new HashMap<>();

    public void addError(String field, String message){
        if(errors.containsKey(field) && errors.get(field).endsWith("is required.")){
            // The required field error should always take priority
            return;
        }

        errors.put(field, message);
    }
}
