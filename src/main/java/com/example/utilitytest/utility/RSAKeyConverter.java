package com.example.utilitytest.utility;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKeyConverter {

	public static String privateKeyToString(RSAPrivateKey privateKey) {
		return Base64.getEncoder().encodeToString(privateKey.getEncoded());
	}

	public static String publicKeyToString(RSAPublicKey publicKey) {
		return Base64.getEncoder().encodeToString(publicKey.getEncoded());
	}

	public static RSAPrivateKey stringToPrivateKey(String key) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(key);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return (RSAPrivateKey)keyFactory.generatePrivate(spec);
	}

	public static RSAPublicKey stringToPublicKey(String key) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(key);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return (RSAPublicKey)keyFactory.generatePublic(spec);
	}

	public static void main(String[] args) throws Exception {
		// Generate RSA key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();

		// Convert keys to strings
		String privateKeyString = privateKeyToString((RSAPrivateKey)keyPair.getPrivate());
		String publicKeyString = publicKeyToString((RSAPublicKey)keyPair.getPublic());

		System.out.println("Private Key: " + privateKeyString);
		System.out.println("Public Key: " + publicKeyString);

		// Convert strings back to keys
		PrivateKey privateKey = stringToPrivateKey(privateKeyString);
		PublicKey publicKey = stringToPublicKey(publicKeyString);

		System.out.println("Private Key (reconstructed): " + privateKey);
		System.out.println("Public Key (reconstructed): " + publicKey);
	}
}