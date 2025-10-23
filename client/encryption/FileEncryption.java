package encryption;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import streamciphers.AES_GCM;

public class FileEncryption {

    public String ciphersuite;

    public FileEncryption(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] encrypt(byte[] data) throws Exception {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return AES_GCM.encryptGCM(data);
            case "AES_256/CBC/PKCS5Padding":
                // Implement AES_256/CBC/PKCS5Padding encryption
                break;
            case "ChaCha20-Poly1305":
                // ChaCha20 chacha20 = new ChaCha20();
                // return chacha20.encrypt(data);
                return encrypt_CHACHA20_Poly1305(data);
            default:
                System.out.println("Unsupported ciphersuite.");
                break;
        }
        return null;
    }

    public String getCypherSuite() {
        return this.ciphersuite;
    }

   

    private byte[] encrypt_CHACHA20_Poly1305(byte[] data) throws Exception {
        byte[] keyBytes = new byte[]{
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};

        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        int counter = 1;
        SecretKeySpec key = new SecretKeySpec(keyBytes, "ChaCha20");

        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, key, param);

        return cipher.doFinal(data);
    }
}
