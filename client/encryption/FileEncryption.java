package encryption;

import streamciphers.AES_CBC_Padding;
import streamciphers.AES_GCM;
import streamciphers.ChaCha20;

public class FileEncryption {

    public String ciphersuite;

    public FileEncryption(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] encrypt(byte[] data) throws Exception {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return AES_GCM.encrypt(data);
            case "AES_256/CBC/PKCS5Padding":
                return AES_CBC_Padding.encrypt(data);
            case "ChaCha20-Poly1305":
                return ChaCha20.encrypt(data);
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
