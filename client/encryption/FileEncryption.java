package encryption;

public class FileEncryption {

    public String ciphersuite;

    public void main(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] encrypt(String cyphersuite, byte[] data) {
        switch (ciphersuite) {
            case "AES_256/GCM/NoPadding":
                // Implement AES_256/GCM/NoPadding encryption
                return encrypt_AES_GCM();
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

    public byte[] encrypt_AES_GCM() {
        return null;
    }
}
