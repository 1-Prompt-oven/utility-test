package com.example.utilitytest.utility;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertThrows;

@Log4j2
@SpringBootTest
public class EncrypterTest {

    @Autowired
    private static Encrypter encrypter;

    @Test
    void testMakeKey() {
        try {
            System.out.print("this is key: ");
            SecretKey generated = encrypter.generateKey();
            System.out.println(generated.getEncoded());
        } catch (Exception e) {}
    }

    @Test
    void testEncrypt() {
        String plainText = "Hello World";
        try{
            String encrypted = encrypter.encrypt(plainText,encrypter.generateKey());
            System.out.println(encrypted);
        } catch (Exception e){}
    }

    @Test
    void testDecrypt() {
        String plainText = "Hello World";
        try {
            SecretKey Key = encrypter.generateKey();
            String encrypted = encrypter.encrypt(plainText,Key);
            System.out.println(encrypted);
            String decoded = encrypter.decrypt(encrypted,Key);
            System.out.println(decoded);
            boolean passed = plainText.equals(decoded);
        } catch (Exception e) {}
    }

}
