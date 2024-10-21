package com.example.utilitytest.utility;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtSecret {

	@Value("jwt.rsa.privatekey")
	String stringPrivateKey;
	@Value("jwt.rsa.publickey")
	String stringPublicKey;

	RSAPrivateKey privateKey = null;
	RSAPublicKey publicKey = null;

	public JwtSecret() throws Exception {
		privateKey = RSAKeyConverter.stringToPrivateKey(stringPrivateKey);
		publicKey = RSAKeyConverter.stringToPublicKey(stringPublicKey);
	}

	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

	public RSAPublicKey getPublicKey() {
		return publicKey;
	}
}
