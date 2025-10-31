package streamciphers;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static encryption.KeywordSecurity.bytesToHex;

public class AES_CBC_Padding {

    // como diz no enunciado The client splits the file into blocks, encrypts each
    // block, generates a MAC or digital signature for integrity and authenticity,
    // and sends the blocks to the server along with metadata keywords, e.g.,
    // finance, Q3
    // o mac será feito a blocks ja encriptados
    private static final byte[] MAC_KEY_BYTES = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    public AES_CBC_Padding() {
    }

    private static final SecretKeySpec MAC_KEY = new SecretKeySpec(MAC_KEY_BYTES, "HmacSHA256");

    public static byte[] encrypt(byte[] data, SecretKey passwordKey) throws Exception {
        SecretKeySpec cipherKey = new SecretKeySpec(passwordKey.getEncoded(), "AES");

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivSpec);

        byte[] cipherText = cipher.doFinal(data);

        // inicio hmac
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(MAC_KEY);
        mac.update(iv);
        mac.update(cipherText);
        byte[] macResult = mac.doFinal();

        ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherText.length + macResult.length);
        buffer.put(iv);
        buffer.put(cipherText);
        buffer.put(macResult);

        return buffer.array();
    }

    public static byte[] decrypt(byte[] encryptedData, SecretKey passwordKey) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

        byte[] iv = new byte[16];
        byteBuffer.get(iv);
        int macLength = 32;
        byte[] cipherText = new byte[byteBuffer.remaining() - macLength];
        byteBuffer.get(cipherText);

        byte[] macReceived = new byte[macLength];
        byteBuffer.get(macReceived);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(MAC_KEY);
        mac.update(iv);
        mac.update(cipherText);
        byte[] macResult = mac.doFinal();

        // ver hmacs por block e validacao de mac
        System.out.println("MAC Received: " + bytesToHex(macReceived));
        System.out.println("MAC Calculated: " + bytesToHex(macResult));
        for (int i = 0; i < macLength; i++) {
            if (macReceived[i] != macResult[i]) {
                throw new SecurityException("MAC verification failed.");
            }
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, passwordKey, ivSpec);

        return cipher.doFinal(cipherText);
    }

}
