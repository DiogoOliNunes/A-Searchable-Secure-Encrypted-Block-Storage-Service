package streamciphers;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.security.*;

/**
 * Cifra simetrica using teh ChaCha20 (or ChaCha20-Poly1305 Alg.)
 */
public class ChaCha20 {

    private byte[] nonce;
    private int counter = 1;
    private SecretKeySpec key;
    private ChaCha20ParameterSpec param;
    private Cipher cipher;

    public ChaCha20() {
        this.nonce = new byte[12];
        byte[] keyBytes = new byte[] {
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef };

        new SecureRandom().nextBytes(nonce);
        this.counter = 1;

        this.param = new ChaCha20ParameterSpec(nonce, counter);
        this.key = new SecretKeySpec(keyBytes, "ChaCha20");

        try {
            this.cipher = Cipher.getInstance("ChaCha20");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] data) throws Exception {
        this.cipher.init(Cipher.ENCRYPT_MODE, this.key, this.param);
        return this.cipher.doFinal(data);
    }

    public byte[] decrypt(byte[] data) throws Exception {
        this.cipher.init(Cipher.DECRYPT_MODE, this.key, this.param);
        return this.cipher.doFinal(data);
    }

    /*
     * byte[] nonce = new byte[12];
     * // Will generate it as a secure randm nonce :-)
     * 
     * new SecureRandom().nextBytes(nonce);
     * 
     * int counter = 1; // Need an initialized counter as integer
     * // Counter conventionaly = 1 but can use other values
     * 
     * SecretKeySpec key = new SecretKeySpec(keyBytes, "ChaCha20");
     * 
     * ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
     * Cipher cipher = Cipher.getInstance("ChaCha20");
     * 
     * System.out.println("key   : " + Utils.toHex(keyBytes));
     * System.out.println("input : " + Utils.toHex(input));
     * 
     * // encryption
     * cipher.init(Cipher.ENCRYPT_MODE, key, param);
     * byte[] cipherText = cipher.doFinal(input);
     * 
     * System.out.println("cipher: " + Utils.toHex(cipherText));
     * 
     * // decryption
     * cipher.init(Cipher.DECRYPT_MODE, key, param);
     * byte[] plaintText = cipher.doFinal(input);
     * 
     * System.out.println("plaintext: " + Utils.toHex(plaintText));
     */
}
