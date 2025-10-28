package encryption;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import streamciphers.AES_CBC_Padding;
import streamciphers.AES_GCM;

public class FileDecryption {

    public String ciphersuite;

    public void main(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] decrypt(String ciphersuite, byte[] data) throws Exception {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return AES_GCM.decryptGCM(data);
            case "AES_256/CBC/PKCS5Padding":
                return AES_CBC_Padding.decrypt(data);
            case "ChaCha20-Poly1305":
                return decrypt_CHACHA20_Poly1305(data);
            default:
                System.out.println("Unsupported ciphersuite.");
                break;}
        return null;
    }

    private byte[] decrypt_CHACHA20_Poly1305(byte[] data) throws Exception {
        byte[] nonce = new byte[12];
        byte[] keyBytes = new byte[]{
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};

        new SecureRandom().nextBytes(nonce);
        int counter = 1;

        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "ChaCha20");

        try {
            Cipher cipher = Cipher.getInstance("ChaCha20");
            cipher.init(Cipher.DECRYPT_MODE, key, param);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
