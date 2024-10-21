package com.example.utilitytest.utility;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

@Component
public class JwtProvider {

	// nimbusds's jwt claim default set's data
	// todo: change issuer and audience to your own
	String jwtissuer = "Prompt Oven Service development group";
	List<String> jwtaudience = List.of("prompt oven service");
	//Hint of JWT token Encryption type
	// RSA-OAEP-512 + ASE/GCM 256
	JWEHeader header = new JWEHeader(
		JWEAlgorithm.RSA_OAEP_512,
		EncryptionMethod.A256GCM
	);
	
	@Autowired
	private JwtSecret jwtSecret;
	RSAPrivateKey privateKey = jwtSecret.getPrivateKey();
	RSAPublicKey publicKey = jwtSecret.getPublicKey();

	@Value("${jwt.expiration.refresh}")
	long refreshExpiration;
	@Value("${jwt.expiration.access}")
	long accessTokenExpiration;

	public String issueRefresh(int requestedExpiration, String authJWT) {

		Date now = new Date();
		String userUID = getClaimOfToken(authJWT, "subject");

		//Create JWT claims
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
			.issuer(jwtissuer)
			.subject(userUID)
			.audience(jwtaudience)
			.notBeforeTime(now)
			.issueTime(now)
			.expirationTime(new Date(now.getTime() +
				refreshExpiration * requestedExpiration))
			//Token is usable for user request days
			.jwtID(UUID.randomUUID().toString())
			.build();

		EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

		RSAEncrypter encrypter = new RSAEncrypter(publicKey);

		try {
			jwt.encrypt(encrypter);
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
		//return serialized jwt Token
		return jwt.serialize();
	}

	public String issueRefresh(String authJWT) {

		Date now = new Date();
		String userUID = getClaimOfToken(authJWT, "subject");

		//Create JWT claims
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
			.issuer(jwtissuer)
			.subject(userUID)
			.audience(jwtaudience)
			.notBeforeTime(now)
			.issueTime(now)
			.expirationTime(new Date(now.getTime() +
				refreshExpiration))
			//Token is usable for user default refresh token life is 1 day
			.jwtID(UUID.randomUUID().toString())
			.build();

		EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

		RSAEncrypter encrypter = new RSAEncrypter(publicKey);

		try {
			jwt.encrypt(encrypter);
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
		//return serialized jwt Token
		return jwt.serialize();
	}

	public String refreshByToken(String refreshToken) {
		try {
			String userUID = getClaimOfToken(refreshToken, "subject");
			return issueJwt(userUID, false);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String issueJwt(String userUID, Boolean is2ndAuthed) {

		Date now = new Date();

		//Create JWT claims
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
			.issuer(jwtissuer)
			.subject(userUID)
			.audience(jwtaudience)
			.notBeforeTime(now)
			.issueTime(now)
			.expirationTime(new Date(now.getTime() + accessTokenExpiration))
			//Token is usable for 30 minutes
			.jwtID(UUID.randomUUID().toString())
			.claim("2nd-authed", is2ndAuthed)
			.build();

		EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

		RSAEncrypter encrypter = new RSAEncrypter(publicKey);

		try {
			jwt.encrypt(encrypter);
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}

		//return serialized jwt Token
		return jwt.serialize();
	}

	// parse serialized token value to token object
	private EncryptedJWT parseToken(String serializedJWT) {
		EncryptedJWT candidateToken = null;
		try {
			candidateToken = EncryptedJWT.parse(serializedJWT);
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}

		return candidateToken;
	}

	// decrypt token
	private EncryptedJWT decryptToken(EncryptedJWT token) {

		RSADecrypter decrypter = new RSADecrypter(privateKey);

		try {
			token.decrypt(decrypter);
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
		return token;
	}

	private boolean validateToken(JWTClaimsSet claims) {
		boolean vaildation = false;

		String issuer = claims.getIssuer();
		Date expire = claims.getExpirationTime();
		Date now = new Date();
		List<String> audience = claims.getAudience();
		if (issuer == jwtissuer && audience.equals(jwtaudience) && expire.before(now)) {
			vaildation = true;
		}
		return vaildation;
	}

	//get values of token
	public String getClaimOfToken(String recievedToken, String typeOfClaim) {
		try {
			EncryptedJWT targetToken = decryptToken(parseToken(recievedToken));
			JWTClaimsSet claimsSet = targetToken.getJWTClaimsSet();
			if (validateToken(claimsSet)) {
				return claimsSet.getClaim(typeOfClaim).toString();
			} else {
				throw new RuntimeException("token expired");
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public Date getTokenExpiration(String recievedToken) {
		try {
			EncryptedJWT targetToken = decryptToken(parseToken(recievedToken));
			JWTClaimsSet claimsSet = targetToken.getJWTClaimsSet();
			if (validateToken(claimsSet)) {
				return claimsSet.getExpirationTime();
			} else {
				throw new RuntimeException("token expired");
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}

