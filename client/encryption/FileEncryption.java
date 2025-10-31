package encryption;

import javax.crypto.SecretKey;

import streamciphers.AES_CBC_Padding;
import streamciphers.AES_GCM;
import streamciphers.ChaCha20;
import streamciphers.PBKDF2;

public class FileEncryption {

    public String ciphersuite;
    public PBKDF2 pbkdf2;

    public FileEncryption(String ciphersuite) throws Exception {
        this.ciphersuite = ciphersuite;
        pbkdf2 = new PBKDF2();
    }

    public byte[] encrypt(byte[] data, SecretKey passwordKey) throws Exception {

        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return AES_GCM.encrypt(data, passwordKey);
            case "AES_256/CBC/PKCS5Padding":
                return AES_CBC_Padding.encrypt(data, passwordKey);
            case "ChaCha20-Poly1305":
                return ChaCha20.encrypt(data, passwordKey);
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
