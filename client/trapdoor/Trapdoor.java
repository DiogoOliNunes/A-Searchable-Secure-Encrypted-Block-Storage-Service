package trapdoor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Trapdoor {
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    public static byte[] createTrapdoor(String keyword, byte[] key) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(spec);
        return mac.doFinal(keyword.getBytes("UTF-8"));
    }

    public static String trapdoorHex(String keyword, byte[] key) throws Exception {
        return bytesToHex(createTrapdoor(keyword, key));
    }


    public static String bytesToHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hex[j * 2] = HEX_ARRAY[v >>> 4];
            hex[j * 2 + 1] = HEX_ARRAY[v & 0x0F]; 
        }
        return new String(hex);
    }
}
