package encryption;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import streamciphers.*;

public class FileEncryption {

    public String ciphersuite;

    public FileEncryption(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] encrypt(byte[] data) throws Exception {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                // Implement AES_256/GCM/NoPadding encryption
                return encrypt_AES_GCM(data);
            case "AES_256/CBC/PKCS5Padding":
                // Implement AES_256/CBC/PKCS5Padding encryption
                break;
            case "ChaCha20-Poly1305":
                // Implement ChaCha20-Poly1305 encryption
                ChaCha20 chacha20 = new ChaCha20();
                return chacha20.encrypt(data);
            default:
                System.out.println("Unsupported ciphersuite.");
            break;
        }
        return null;
    }

    public byte[] decrypt(byte[] data) throws Exception {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return encrypt_AES_GCM(data);
            case "AES_256/CBC/PKCS5Padding":
                // Implement AES_256/CBC/PKCS5Padding decryption
                break;
            case "ChaCha20-Poly1305":
                // Implement ChaCha20-Poly1305 decryption
                ChaCha20 chacha20 = new ChaCha20();
                return chacha20.decrypt(data);
            default:
                System.out.println("Unsupported ciphersuite.");
            break;
        }
        return null;
    }

    public byte[] encrypt_AES_GCM(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException {
        
        byte[] keyBytes = new byte[] {
            0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,  0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13,  0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B,  0x1C, 0x1D, 0x1E, 0x1F
    };
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

    byte[] ivBytes = new byte[12];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(ivBytes);

    try {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = cipher.doFinal(data);

        ByteBuffer byteBuffer = ByteBuffer.allocate(ivBytes.length + cipherText.length);
        byteBuffer.put(ivBytes);
        byteBuffer.put(cipherText);

        return byteBuffer.array();
    } catch (Exception e) {
        e.printStackTrace();
    }
    return null;
}
}
