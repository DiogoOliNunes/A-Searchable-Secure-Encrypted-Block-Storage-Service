
import encryption.*;
import streamciphers.PBKDF2;

import java.io.*;
import java.net.*;
import java.util.*;

import javax.crypto.SecretKey;

public class CLTest {
    private static final int PORT = 5000;
    private static final int BLOCK_SIZE = 4096;
    private static final String INDEX_FILE = "client_index.ser";

    private static Map<String, List<String>> fileIndex = new HashMap<>();
    private static KeywordSecurity kwSec;

    public static void main(String[] args) throws Exception {
        loadIndex();
        kwSec = new KeywordSecurity();

        if (args.length < 1) {
            System.out.println("Usage:");
            System.out.println("  java -cp bin CLTest PUT <path/file> <keywords>");
            System.out.println("  java -cp bin CLTest LIST");
            System.out.println("  java -cp bin CLTest SEARCH <keywords>");
            System.out.println("  java -cp bin CLTest GET <file> <path/dir>");
            System.out.println("  java -cp bin CLTest GET <keywords> <dir>");
            System.out.println("  java -cp bin CLTest GET CHECKINTEGRITY <path/file>");
            return;
        }

        String cmd = args[0].toUpperCase();

        try (Socket socket = new Socket("localhost", PORT);
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            switch (cmd) {
                case "PUT":
                    if (args.length < 3) {
                        System.out.println("Usage: cltest PUT <path/file> <keywords>");
                        return;
                    }
                    doPut(args[1], args[2], out, in);
                    break;

                case "LIST":
                    doList(out, in);
                    break;

                case "SEARCH":
                    if (args.length < 2) {
                        System.out.println("Usage: cltest SEARCH <keywords>");
                        return;
                    }
                    doSearch(args[1], out, in);
                    break;

                case "GET":
                    if (args.length == 3)
                        doGet(args[1], args[2], out, in);
                    else if (args.length == 4 && args[1].equalsIgnoreCase("CHECKINTEGRITY"))
                        doCheckIntegrity(args[2], out, in);
                    else
                        System.out.println("Usage: cltest GET <file> <dir> or cltest GET CHECKINTEGRITY");
                    break;

                default:
                    System.out.println("Unknown command: " + cmd);
            }
        } finally {
            saveIndex();
        }
    }

    private static void doPut(String path, String kwLine, DataOutputStream out, DataInputStream in) throws Exception {
        File file = new File(path);
        if (!file.exists()) {
            System.out.println("File not found.");
            return;
        }

        String[] config = readCryptoConfig();
        String ciphersuite = config[0].split(" ")[1];
        String password = config[2].split(" ")[1];

        PBKDF2 pbkdf2 = new PBKDF2(password.toCharArray());
        SecretKey key = pbkdf2.deriveKey(file.getName(), ciphersuite);

        FileEncryption encryptor = new FileEncryption(ciphersuite, password.toCharArray());
        List<String> keywords = Arrays.asList(kwLine.split(","));

        int blockNum = 0;
        byte[] buffer = new byte[BLOCK_SIZE];

        try (FileInputStream fis = new FileInputStream(file)) {
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] blockData = Arrays.copyOf(buffer, bytesRead);
                blockData = encryptor.encrypt(blockData, key);

                String blockId = file.getName() + "_block_" + blockNum++;
                String encryptedBlockId = KeywordSecurity.bytesToHex(kwSec.encryptKeyword(blockId));

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(encryptedBlockId);
                out.writeInt(blockData.length);
                out.write(blockData);

                if (blockNum == 1) {
                    out.writeInt(keywords.size());
                    for (String kw : keywords) {
                        String encryptedKw = KeywordSecurity.bytesToHex(kwSec.encryptKeyword(kw.trim().toLowerCase()));
                        out.writeUTF(encryptedKw);
                    }
                } else {
                    out.writeInt(0);
                }

                out.flush();
                String response = in.readUTF();
                if (!response.equals("OK")) {
                    System.out.println("Error storing block: " + blockId);
                    return;
                }
            }
        }

        System.out.println("File uploaded successfully.");
    }

    private static void doList(DataOutputStream out, DataInputStream in) throws IOException {
        out.writeUTF("LIST");
        out.flush();
        int count = in.readInt();
        System.out.println("Files in server:");
        for (int i = 0; i < count; i++)
            System.out.println(" - " + in.readUTF());
    }

    private static void doSearch(String keyword, DataOutputStream out, DataInputStream in) throws Exception {
        out.writeUTF("SEARCH");
        String encryptedKw = KeywordSecurity.bytesToHex(kwSec.encryptKeyword(keyword));
        out.writeUTF(encryptedKw);
        out.flush();
        int count = in.readInt();
        System.out.println();
        System.out.println("Search results:");
        for (int i = 0; i < count; i++) {
            System.out.println(" - " + in.readUTF());
        }
    }

    private static void doGet(String filename, String dir, DataOutputStream out, DataInputStream in) throws Exception {
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
            System.out.println();
            System.out.println("File not found in local index.");
            return;
        }

        String[] config = readCryptoConfig();
        String ciphersuite = config[0].split(" ")[1];
        //String password = config[2].split(" ")[1];
        FileDecryption decryptor = new FileDecryption(ciphersuite);

        try (FileOutputStream fos = new FileOutputStream(dir + "retrieved_" + filename)) {
            for (String blockId : blocks) {
                String encryptedBlockId = KeywordSecurity.bytesToHex(kwSec.encryptKeyword(blockId));
                out.writeUTF("GET_BLOCK");
                out.writeUTF(encryptedBlockId);
                out.flush();
                int length = in.readInt();
                if (length == -1) {
                    System.out.println("Block not found: " + blockId);
                    continue;
                }

                byte[] data = new byte[length];
                in.readFully(data);
                byte[] decrypted = decryptor.decrypt(data, filename);
                fos.write(decrypted);
                System.out.print(".");
            }
        }
        System.out.println();
        System.out.println("File reconstructed: retrieved_" + filename);
    }

    private static void doCheckIntegrity(String filePath, DataOutputStream out, DataInputStream in) throws IOException {
        out.writeUTF("CHECKINTEGRITY");
        out.writeUTF(filePath);
        out.flush();
        boolean integrityCheck = in.readBoolean();
        System.out.println(integrityCheck ? "Integrity was fulfilled" : "Integrity was compromised");
    }

    private static String[] readCryptoConfig() {
        File configFile = new File("client/cryptoconfig.txt");
        try (BufferedReader reader = new BufferedReader(new FileReader(configFile))) {
            return reader.lines().toArray(String[]::new);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void saveIndex() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(INDEX_FILE))) {
            oos.writeObject(fileIndex);
        } catch (IOException e) {
            System.err.println("Failed to save index: " + e.getMessage());
        }
    }

    private static void loadIndex() {
        File f = new File(INDEX_FILE);
        if (!f.exists())
            return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            fileIndex = (Map<String, List<String>>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Failed to load index: " + e.getMessage());
        }
    }
}
