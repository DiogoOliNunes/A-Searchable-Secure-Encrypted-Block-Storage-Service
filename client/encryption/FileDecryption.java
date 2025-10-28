package encryption;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import streamciphers.AES_CBC_Padding;
import streamciphers.AES_GCM;
import streamciphers.ChaCha20;

public class FileDecryption {

    public String ciphersuite;

    public void main(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] decrypt(String ciphersuite, byte[] data) throws Exception {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return AES_GCM.decrypt(data);
            case "AES_256/CBC/PKCS5Padding":
                return AES_CBC_Padding.decrypt(data);
            case "ChaCha20-Poly1305":
                return ChaCha20.decrypt(data);
            default:
                System.out.println("Unsupported ciphersuite.");
                break;}
        return null;
    }
}
