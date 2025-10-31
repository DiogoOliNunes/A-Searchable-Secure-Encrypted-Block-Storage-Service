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
    private static final char[] KS_PASSWORD = "password".toCharArray();

    private static KeyStore store;
    private File storeFile;

    public PBKDF2() throws Exception {
        PBKDF2.store = KeyStore.getInstance("JCEKS");
        this.storeFile = new File("client_keystore.jceks");

        if (storeFile.exists() && storeFile.length() > 0) {
            try (FileInputStream in = new FileInputStream(storeFile)) {
                store.load(in, KS_PASSWORD);
            } catch (Exception e) {
                System.out.println("Keystore corrupted, creating a new one");
                store.load(null, KS_PASSWORD);
                try (FileOutputStream out = new FileOutputStream(storeFile)) {
                    store.store(out, KS_PASSWORD);
                }
            }
        } else {
            store.load(null, KS_PASSWORD);
            try (FileOutputStream out = new FileOutputStream(storeFile)) {
                store.store(out, KS_PASSWORD);
            }
        }
    }

    private SecretKey pbkdf2(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LEN_BITS);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = keyFactory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, "AES");
    }

    public SecretKey deriveKey(String fileName, String password, String ciphersuite) throws Exception {
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt);

        SecretKey passwordKey = pbkdf2(password, salt);
        SecretKeyEntry keyEntry = new SecretKeyEntry(passwordKey);
        store.setEntry(fileName, keyEntry, new PasswordProtection(KS_PASSWORD));

        SecretKeySpec spec = new SecretKeySpec(salt, ciphersuite);
        SecretKeyEntry saltEntry = new SecretKeyEntry(spec);
        store.setEntry(fileName + " salt", saltEntry, new PasswordProtection(KS_PASSWORD));

        try (FileOutputStream out = new FileOutputStream(storeFile)) {
            store.store(out, KS_PASSWORD);
        }
        return passwordKey;
    }

    public static SecretKey getKey(String fileName, String password) throws Exception {
        if (store == null) {
            store = KeyStore.getInstance("JCEKS");
            File storeFile = new File("client_keystore.jceks");
            try (FileInputStream in = new FileInputStream(storeFile)) {
                store.load(in, KS_PASSWORD);
            }
        }
        SecretKeyEntry saltEntry = (SecretKeyEntry) store.getEntry(fileName + " salt",
                new PasswordProtection(KS_PASSWORD));
        if (saltEntry == null) {
            System.out.println("Salt not found in the keystore");
        }
        byte[] salt = saltEntry.getSecretKey().getEncoded();

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LEN_BITS);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        byte[] keyBytes = keyFactory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, "AES");
    }
}
