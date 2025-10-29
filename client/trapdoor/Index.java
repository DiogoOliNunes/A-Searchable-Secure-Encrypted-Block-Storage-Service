package trapdoor;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.SecureRandom;

public class Index {
    private static final int NONCE_LEN = 12;
    private static final int TAG_LEN_BITS = 128;

    public static byte[] encryptIndexEntry(byte[] plaintext, byte[] key) throws Exception {
        byte[] nonce = new byte[NONCE_LEN];
        new SecureRandom().nextBytes(nonce);

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LEN_BITS, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        byte[] ct = cipher.doFinal(plaintext);

        byte[] out = new byte[nonce.length + ct.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ct, 0, out, nonce.length, ct.length);
        return out;
    }

    public static byte[] decryptIndexEntry(byte[] nonceAndCiphertext, byte[] key) throws Exception {
        if (nonceAndCiphertext.length < NONCE_LEN) {
            throw new IllegalArgumentException("bad index blob");
        }
        byte[] nonce = new byte[NONCE_LEN];
    }
}
