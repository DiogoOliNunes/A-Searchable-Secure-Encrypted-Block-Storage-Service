package encryption;

import javax.crypto.SecretKey;
import streamciphers.AES_CBC_Padding;
import streamciphers.AES_GCM;
import streamciphers.ChaCha20;
import static streamciphers.PBKDF2.getKey;

public class FileDecryption {

    public CryptoReader ciphersuite;
    public AES_GCM aes_gcm;
    public AES_CBC_Padding AES_CBC_Padding;
    public ChaCha20 ChaCha20;

    public FileDecryption(CryptoReader ciphersuite) {
        this.ciphersuite = ciphersuite;
        aes_gcm = new AES_GCM();
        AES_CBC_Padding = new AES_CBC_Padding();
        ChaCha20 = new ChaCha20();
    }

    public byte[] decrypt(byte[] data, String fileName) throws Exception {
        SecretKey passwordKey = getKey(fileName);

        switch (ciphersuite.getAlgorithm()) {
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
