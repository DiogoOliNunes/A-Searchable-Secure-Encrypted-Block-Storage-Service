package encryption;
public class CryptoReader {
    
    private String algorithm;
    private String keySize;
    private String hmac;
    private String hmacKey;

    public CryptoReader(String algorithm, String keySize, String hmac, String hmacKey) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.hmac = hmac;
        this.hmacKey = hmacKey;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getKeySize() {
        return keySize;
    }

    public String getHmac() {
        return hmac;
    }

    public String getHmacKey() {
        return hmacKey;
    }

     public boolean useHmac() {
        return hmac != null && !hmac.isEmpty();
    }

    @Override
    public String toString() {
        return "CryptoReader{" +
                "algorithm='" + algorithm + '\'' +
                ", keySize='" + keySize + '\'' +
                ", hmac='" + hmac + '\'' +
                ", hmacKey='" + hmacKey + '\'' +
                '}';
    }
}
