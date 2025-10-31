package streamciphers;

import encryption.CryptoReader;
import static encryption.KeywordSecurity.bytesToHex;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_CBC_Padding {

    // como diz no enunciado The client splits the file into blocks, encrypts each
    // block, generates a MAC or digital signature for integrity and authenticity,
    // and sends the blocks to the server along with metadata keywords, e.g.,
    // finance, Q3
    // o mac será feito a blocks ja encriptados

    private static String MAC_ALGORITHM;
    private static SecretKeySpec macKey;

    public AES_CBC_Padding(CryptoReader config) throws Exception {
        // Read algorithm (e.g., "HmacSHA256")
        MAC_ALGORITHM = config.getHmac();

        // Parse key or key size from config
        String keyConfig = config.getHmacKey();
        if (keyConfig == null || keyConfig.isEmpty()) {
            throw new IllegalArgumentException("Missing HMAC key in config file.");
        }

        byte[] keyBytes;

        if (keyConfig.matches("^\\d+$")) {
            // If numeric → treat as key size in bits and generate random key
            int keySizeBits = Integer.parseInt(keyConfig);
            keyBytes = new byte[keySizeBits / 8];
            new SecureRandom().nextBytes(keyBytes);
        } else if (keyConfig.matches("^[0-9A-Fa-f]+$")) {
            // If hex → convert to bytes
            keyBytes = hexStringToByteArray(keyConfig);
        } else {
            // Otherwise → treat as text and use UTF-8 bytes
            keyBytes = keyConfig.getBytes(StandardCharsets.UTF_8);
        }

        this.macKey = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
    }

    public static byte[] encrypt(byte[] data, SecretKey passwordKey) throws Exception {
        SecretKeySpec cipherKey = new SecretKeySpec(passwordKey.getEncoded(), "AES");

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(data);

        // Generate MAC
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
        mac.update(iv);
        mac.update(cipherText);
        byte[] macResult = mac.doFinal();

        // Concatenate IV + ciphertext + MAC
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

        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
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

    private byte[] hexStringToByteArray(String keyHex) {
        int len = keyHex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(keyHex.charAt(i), 16) << 4)
                    + Character.digit(keyHex.charAt(i + 1), 16));
        }
        return data;
    }

}
