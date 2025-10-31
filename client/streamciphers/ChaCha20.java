package streamciphers;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.ChaCha20ParameterSpec;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.util.Arrays;

//Cifra simetrica using teh ChaCha20 (or ChaCha20-Poly1305 Alg.)

public class ChaCha20 {

    private static final int COUNTER = 1;
    private static final int NONCE_SIZE = 12;

    public ChaCha20() {
    }

    public static byte[] encrypt(byte[] data, SecretKey passwordKey) throws Exception {
        SecretKeySpec key = new SecretKeySpec(passwordKey.getEncoded(), "ChaCha20");

        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);

        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, COUNTER);
        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, key, param);

        byte[] cipherText = cipher.doFinal(data);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(nonce);
        output.write(cipherText);

        return output.toByteArray();
    }

    public static byte[] decrypt(byte[] data, SecretKey passwordKey) throws Exception {
        if (data.length < NONCE_SIZE)
            throw new IllegalArgumentException("Encrypted data too short");

        byte[] nonce = Arrays.copyOfRange(data, 0, NONCE_SIZE);
        byte[] cipherText = Arrays.copyOfRange(data, NONCE_SIZE, data.length);

        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, COUNTER);
        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.DECRYPT_MODE, passwordKey, param);

        return cipher.doFinal(cipherText);
    }
}
