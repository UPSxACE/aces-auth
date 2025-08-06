package com.upsxace.aces_auth_service.features.apps.utils;

import com.upsxace.aces_auth_service.lib.utils.AesUtils;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Component
@Lazy
public class AesKeyGenerator {
    @Value("${config.apps.aes-secret-key}")
    private String AES_SECRET_KEY;

    private final String DELIMITER = ":::";

    @PostConstruct
    public void validateBean() {
        if (AES_SECRET_KEY == null || AES_SECRET_KEY.isBlank()) {
            throw new IllegalStateException("APPS_AES_SECRET_KEY environment variable is not set");
        }
    }

    private SecretKey getSecretKey(){
        return AesUtils.decodeKey(AES_SECRET_KEY);
    }

    public String encryptClientSecret(String clientSecret) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        var secretKey = getSecretKey();
        var gcmParameterSpec = AesUtils.generateIv();
        var cipherText = AesUtils.encrypt(clientSecret, secretKey, gcmParameterSpec);

        var ivBase64 = Base64.getEncoder().encodeToString(gcmParameterSpec.getIV());

        return cipherText + DELIMITER + ivBase64;
    }

    public String decryptClientSecret(String combinedString) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        var secretKey = getSecretKey();

        String[] parts = combinedString.split(DELIMITER);
        if (parts.length != 2) throw new IllegalArgumentException("Invalid format");
        String cipherText = parts[0];
        String ivBase64 = parts[1];

        byte[] ivDecoded = Base64.getDecoder().decode(ivBase64);
        var iv = new GCMParameterSpec(128, ivDecoded);

        return AesUtils.decrypt(cipherText, secretKey, iv);
    }
}
