package encryption;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileDecryption {
    
     public String ciphersuite;

    public void main(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] decrypt(String ciphersuite, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                return decrypt_AES_GCM(data);

            case "AES_256/CBC/PKCS5Padding":
                // Implement AES_256/CBC/PKCS5Padding encryption
                break;
            case "ChaCha20-Poly1305":
                // Implement ChaCha20-Poly1305 encryption
                break;
            default:
                System.out.println("Unsupported ciphersuite.");
                break;
        }
        return null;
    }

    public byte[] decrypt_AES_GCM(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] keyBytes = new byte[] {
            0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,  0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13,  0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B,  0x1C, 0x1D, 0x1E, 0x1F
    };
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
ByteBuffer byteBuffer = ByteBuffer.wrap(data);
    byte[] ivBytes = new byte[12];
    byteBuffer.get(ivBytes);

    byte[] cipherText = new byte[byteBuffer.remaining()];
    byteBuffer.get(cipherText);

    try {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        return cipher.doFinal(cipherText);
    } catch (Exception e) {
        e.printStackTrace();
    }
    return null;
}
}