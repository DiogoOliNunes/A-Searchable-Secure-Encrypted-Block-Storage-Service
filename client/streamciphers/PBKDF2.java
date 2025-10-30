package streamciphers;

import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class PBKDF2 {

    private static final int SALT_LEN = 16;
    private static final int ITERATIONS = 100000;
    private static final int KEY_LEN_BITS = 256;

    public PBKDF2() {
    }

    private static byte[] pbkdf2(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LEN_BITS);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        return keyFactory.generateSecret(spec).getEncoded();
    }

    public static byte[] deriveKeyBytes(String password) throws Exception {
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt);

        byte[] keyBytes = pbkdf2(password, salt);
        return keyBytes;
    }

    public static SecretKeySpec getKey(String password, byte[] salt, String ciphersuite) throws Exception {
        byte[] keyBytes = pbkdf2(password, salt);
        return new SecretKeySpec(keyBytes, ciphersuite);
    }
}
