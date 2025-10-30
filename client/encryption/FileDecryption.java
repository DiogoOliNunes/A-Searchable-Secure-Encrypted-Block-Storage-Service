package encryption;

import streamciphers.AES_CBC_Padding;
import streamciphers.AES_GCM;
import streamciphers.ChaCha20;

import java.security.KeyStore;
import java.security.KeyStoreException;

import static streamciphers.PBKDF2.getKey;

import javax.crypto.spec.SecretKeySpec;

public class FileDecryption {

    public String ciphersuite;
    public KeyStore store;

    public void main(String ciphersuite, KeyStore store) {
        this.ciphersuite = ciphersuite;
        this.store = store;
    }

    public byte[] decrypt(byte[] data, String password) throws Exception {
        SecretKeySpec key = getKey(password, salt, ciphersuite); // implementar key store a guardar os salts

        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return AES_GCM.decrypt(data, key);
            case "AES_256/CBC/PKCS5Padding":
                return AES_CBC_Padding.decrypt(data, key);
            case "ChaCha20-Poly1305":
                return ChaCha20.decrypt(data, key);
            default:
                System.out.println("Unsupported ciphersuite.");
                break;
        }
        return null;
    }
}
