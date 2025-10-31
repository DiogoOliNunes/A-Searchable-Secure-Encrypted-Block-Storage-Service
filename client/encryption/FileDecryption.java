package encryption;

import streamciphers.AES_CBC_Padding;
import streamciphers.AES_GCM;
import streamciphers.ChaCha20;

import static streamciphers.PBKDF2.getKey;

import javax.crypto.SecretKey;

public class FileDecryption {

    public String ciphersuite;

    public FileDecryption(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] decrypt(byte[] data, String fileName) throws Exception {
        SecretKey passwordKey = getKey(fileName);

        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return AES_GCM.decrypt(data, passwordKey);
            case "AES_256/CBC/PKCS5Padding":
                return AES_CBC_Padding.decrypt(data, passwordKey);
            case "ChaCha20-Poly1305":
                return ChaCha20.decrypt(data, passwordKey);
            default:
                System.out.println("Unsupported ciphersuite.");
                break;
        }
        return null;
    }
}
