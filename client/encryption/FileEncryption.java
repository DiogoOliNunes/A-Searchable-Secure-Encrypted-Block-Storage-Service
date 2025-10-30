package encryption;

import streamciphers.AES_CBC_Padding;
import streamciphers.AES_GCM;
import streamciphers.ChaCha20;

import java.security.KeyStore;
import java.security.KeyStoreException;

import static streamciphers.PBKDF2.deriveKeyBytes;

public class FileEncryption {

    public String ciphersuite;
    public KeyStore store;

    public FileEncryption(String ciphersuite, KeyStore store) {
        this.ciphersuite = ciphersuite;
        this.store = store;
    }

    public byte[] encrypt(byte[] data, String password) throws Exception {
        byte[] keyBytes = deriveKeyBytes(password);

        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return AES_GCM.encrypt(data, keyBytes);
            case "AES_256/CBC/PKCS5Padding":
                return AES_CBC_Padding.encrypt(data, keyBytes);
            case "ChaCha20-Poly1305":
                return ChaCha20.encrypt(data, keyBytes);
            default:
                System.out.println("Unsupported ciphersuite.");
                break;
        }
        return null;
    }

    public String getCypherSuite() {
        return this.ciphersuite;
    } 
}
