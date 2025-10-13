package encryption;

import streamciphers.*;

public class FileEncryption {

    public String ciphersuite;

    public FileEncryption(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] encrypt(byte[] data) throws Exception {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                // Implement AES_256/GCM/NoPadding encryption
                return encrypt_AES_GCM(null);
            case "AES_256/CBC/PKCS5Padding":
                // Implement AES_256/CBC/PKCS5Padding encryption
                break;
            case "ChaCha20-Poly1305":
                // Implement ChaCha20-Poly1305 encryption
                ChaCha20 chacha20 = new ChaCha20();
                return chacha20.encrypt(data);
            default:
                System.out.println("Unsupported ciphersuite.");
            break;
        }
        return null;
    }

    public byte[] decrypt(byte[] data) throws Exception {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                // Implement AES_256/GCM/NoPadding decryption
                break;
            case "AES_256/CBC/PKCS5Padding":
                // Implement AES_256/CBC/PKCS5Padding decryption
                break;
            case "ChaCha20-Poly1305":
                // Implement ChaCha20-Poly1305 decryption
                ChaCha20 chacha20 = new ChaCha20();
                return chacha20.decrypt(data);
            default:
                System.out.println("Unsupported ciphersuite.");
            break;
        }
        return null;
    }

    public byte[] encrypt_AES_GCM(byte[] data) {
        return null;
    }
}
