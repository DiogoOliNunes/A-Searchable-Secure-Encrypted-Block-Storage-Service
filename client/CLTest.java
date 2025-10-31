
import encryption.*;
import java.io.*;
import java.net.*;
import java.util.*;

public class CLTest {
    private static final int PORT = 5000;
    
    private static Map<String, List<String>> fileIndex = new HashMap<>();
    private static FileEncryption encryptor;
    private static KeywordSecurity kwSec;
    private static final String INDEX_FILE = "client_index.ser";
    public static void main(String[] args) throws Exception {
        loadIndex();
        kwSec = new KeywordSecurity();
        if (args.length < 1) {
            System.out.println("Chose your Option:");
            System.out.println("  java -cp bin CLTest put <path/file> <keywords>");
            System.out.println("  java -cp bin CLTest list");
            System.out.println("  java -cp bin CLTest search <keywords>");
            System.out.println("  java -cp bin CLTest get <file> <path/dir>");
            return;
        }

        String cmd = args[0].toUpperCase();

        try (Socket socket = new Socket("localhost", PORT);
             DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            switch (cmd) {
                case "PUT":
                    if (args.length < 3) {
                        System.out.println("Use: java -cp bin CLTest put <path/file> <keywords>");
                        return;
                    }
                    String filePath = args[1];
                    String keywords = args[2];
                    doPut(filePath, keywords, out, in);
                    break;

                case "LIST":
                    out.writeUTF("LIST");
                    out.flush();
                    for (String f : fileIndex.keySet())
                            System.out.println(" - " + f);
                    break;

                case "SEARCH":
                    if (args.length < 2) {
                        System.out.println("Use: java -cp bin CLTest search <keywords>");
                        return;
                    }
                    doSearch(args[1], out, in);
                    break;

                case "GET":
                    if (args.length < 3) {
                        System.out.println("Use: java -cp bin CLTest get <file> <path/dir>");
                        return;
                    }
                    
                    doGet(args[1], args[2], out, in);
                    break;

                default:
                    System.out.println("Unknown command: " + cmd);
            }
        }
    }

    private static void doPut(String path, String kwLine, DataOutputStream out, DataInputStream in) throws Exception {
        File file = new File(path);
        if (!file.exists()) {
            System.out.println("File does not exist.");
            return;
        }

        FileEncryption encryptor = new FileEncryption("AES_256/CBC/PKCS5Padding");
        KeywordSecurity kwSec = new KeywordSecurity();
        List<String> keywords = Arrays.asList(kwLine.split(","));

        byte[] buffer = new byte[4096];
        try (FileInputStream fis = new FileInputStream(file)) {
            int bytesRead;
            int blockNum = 0;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] blockData = Arrays.copyOf(buffer, bytesRead);
                blockData = encryptor.encrypt(blockData);
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
    private static void doGet(String filename, String dir, DataOutputStream out, DataInputStream in) throws Exception {
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
            System.out.println();
            System.out.println("File not found in local index.");
            return;
        }
        try (FileOutputStream fos = new FileOutputStream("retrieved_" + filename)) {
            for (String blockId : blocks) {
                String encryptedBlockId = KeywordSecurity.bytesToHex(kwSec.encryptKeyword(blockId));
                out.writeUTF("GET_BLOCK");
                out.writeUTF(encryptedBlockId);
                out.flush();
                int length = in.readInt();
                if (length == -1) {
                    System.out.println("Block not found: " + blockId);
                    return;
                }
                byte[] data = new byte[length];
                in.readFully(data);
                byte[] decryptedBlock = null;
                try {
                    FileDecryption fileDecryption = new FileDecryption();
                    decryptedBlock = fileDecryption.decrypt("AES_256/CBC/PKCS5Padding", data);

                } catch (Exception e) {
                }
                System.out.print(".");
                fos.write(decryptedBlock);
            }
        } catch (Exception e) {
            System.out.println("The file has been tampered. Aborting command...");
            return;
        }
        System.out.println();
        System.out.println("File reconstructed: retrieved_" + filename);
    }


    private static void doSearch(String keyword, DataOutputStream out, DataInputStream in) throws Exception {
        try {
            out.writeUTF("SEARCH");
            String encryptedKw = KeywordSecurity.bytesToHex(kwSec.encryptKeyword(keyword));
            out.writeUTF(encryptedKw);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
        int count = in.readInt();
        System.out.println();
        System.out.println("Search results:");
        for (int i = 0; i < count; i++) {
            System.out.println(" - " + in.readUTF());
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
