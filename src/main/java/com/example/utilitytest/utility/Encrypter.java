package com.example.utilitytest.utility;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
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

    // 암호화 키를 생성하는 메서드입니다. 백업용 겸 설정파일 내용 업데이트 위한 값 생성 용이에요
    public SecretKey generateKey() throws Exception{
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGO);
        keyGen.init(256); // AES-256 암호화 호출할 거에요
        SecretKey generatedKey = keyGen.generateKey();
        printKey(generatedKey);
        return generatedKey;
    }

    // 생성한 암호화 키를 콘솔(터미널)에 출력하는 메서드입니다. 암호화 키 생성 메서드에서 자동 호출 되어요.
    private void printKey(SecretKey generatedKey) throws Exception {
        System.out.println(generatedKey.getEncoded());
    }
}