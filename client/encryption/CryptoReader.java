package encryption;
public class CryptoReader {
    
    private String ciphersuite;
    private String keySize;
    private String hmac;
    private String hmacKey;

    public CryptoReader(String ciphersuite, String keySize, String hmac, String hmacKey) {
        this.ciphersuite = ciphersuite;
        this.keySize = keySize;
        this.hmac = hmac;
        this.hmacKey = hmacKey;
    }

    public String getCiphersuite() {
        return ciphersuite;
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
                "ciphersuite='" + ciphersuite + '\'' +
                ", keySize='" + keySize + '\'' +
                ", hmac='" + hmac + '\'' +
                ", hmacKey='" + hmacKey + '\'' +
                '}';
    }
}
