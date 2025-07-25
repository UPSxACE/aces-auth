package com.upsxace.aces_auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.NoSuchAlgorithmException;

@SpringBootApplication
public class AcesAuthServiceApplication {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		SpringApplication.run(AcesAuthServiceApplication.class, args);
	}

}
