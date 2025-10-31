package streamciphers;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_GCM {

    public AES_GCM() {
    }

    public static byte[] encrypt(byte[] data, SecretKey passwordKey) throws Exception {
        SecretKeySpec key = new SecretKeySpec(passwordKey.getEncoded(), "AES");
        
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] cipherText = cipher.doFinal(data);

        ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherText.length);
        buffer.put(iv);
        buffer.put(cipherText);
        return buffer.array();
    }

    public static byte[] decrypt(byte[] data, SecretKey passwordKey) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(data);

        byte[] iv = new byte[12];
        byteBuffer.get(iv);

        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, passwordKey, gcmSpec);

        return cipher.doFinal(cipherText);
    }

}