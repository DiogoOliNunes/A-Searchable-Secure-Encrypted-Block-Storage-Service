package streamciphers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.PasswordProtection;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PBKDF2 {

    private static final int SALT_LEN = 16;
    private static final int ITERATIONS = 100000;
    private static final int KEY_LEN_BITS = 256;

    private static KeyStore store;
    private File storeFile;
    private static char[] password;
    private static PasswordProtection protection;

    public PBKDF2(char[] password) throws Exception {
        PBKDF2.store = KeyStore.getInstance("JCEKS");
        this.storeFile = new File("client_keystore.jceks");
        PBKDF2.password = password;
        protection = new PasswordProtection(password);

        if (storeFile.exists() && storeFile.length() > 0) {
            try (FileInputStream in = new FileInputStream(storeFile)) {
                store.load(in, password);
            } catch (Exception e) {
                System.out.println("Keystore corrupted, creating a new one");
                store.load(null, password);
                try (FileOutputStream out = new FileOutputStream(storeFile)) {
                    store.store(out, password);
                }
            }
        } else {
            store.load(null, password);
            try (FileOutputStream out = new FileOutputStream(storeFile)) {
                store.store(out, password);
            }
        }
    }

    private SecretKey pbkdf2(byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LEN_BITS);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = keyFactory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, "AES");
    }

    public SecretKey deriveKey(String fileName, String ciphersuite) throws Exception {
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt);

        SecretKey passwordKey = pbkdf2(salt);
        SecretKeyEntry keyEntry = new SecretKeyEntry(passwordKey);
        store.setEntry(fileName, keyEntry, protection);

        try (FileOutputStream out = new FileOutputStream(storeFile)) {
            store.store(out, password);
        }
        return passwordKey;
    }

    public static SecretKey getKey(String fileName) throws Exception {
        if (store == null) {
            store = KeyStore.getInstance("JCEKS");
            File storeFile = new File("client_keystore.jceks");
            try (FileInputStream in = new FileInputStream(storeFile)) {
                store.load(in, password);
            }
        }
        SecretKeyEntry keyEntry = (SecretKeyEntry) store.getEntry(fileName, protection);
        if (keyEntry == null) {
            System.out.println("Key not found in the keystore");
        }
        SecretKey key = keyEntry.getSecretKey();

        return key;
    }
}
