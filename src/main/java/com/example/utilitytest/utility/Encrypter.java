package com.example.utilitytest.utility;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class Encrypter {

    // 암호화 알고리즘 : AES-256 할 거에요
    private static final String ALGO = "AES";
    // 암호화 키
    private final SecretKey secretKey;

    // 생성자에서 암호화 키를 설정파일로부터 초기화합니다.
    public Encrypter(@Value("${encrypter.secret-key}") String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        this.secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGO);
    }

    // 데이터를 암호화하는 메서드입니다.
    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // 암호화된 데이터를 복호화하는 메서드입니다.
    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = cipher.doFinal(decoded);
        return new String(decryptedData);
    }
}