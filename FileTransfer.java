import java.io.*;
import java.util.*;
import java.util.zip.CRC32;
import java.nio.file.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.net.*;
import javax.crypto.*;
import java.security.NoSuchAlgorithmException;


public class FileTransfer {
    
    public static void main(String[] args) {
        
        if(args.length == 0) {
            System.out.println("PLEASE PROVIDE SOME INPUT");
        } else if(args[0].toLowerCase().equals("makekeys")) {
            
            genKeys();
            
        } else if(args[0].toLowerCase().equals("server")) {
            
            if(args.length != 3) {
                System.out.println("Incorrect number of parameters for server function detected, please try again.");
            } else {
                try {
                    server(args);
                }catch(Exception e) {
                    System.out.println("Something went wrong...");
                    e.printStackTrace();
                }
            }
            
        }  else if(args[0].toLowerCase().equals("client")) {// End of if args[0] = server
            if(args.length != 4) {
                System.out.println("Incorrecto number of parameters for client function...");
            } else {
                client(args);
            }
        }
            
    } // End of main
    
    
    private static void genKeys() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(4096); // you can use 2048 for faster key generation
            KeyPair keyPair = gen.genKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
                
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("public.bin")))) {
                oos.writeObject(publicKey);
            }
            
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) {
                oos.writeObject(privateKey);
            }
                
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace(System.err);
        }
        
        System.out.println("Keys dumped into \"public.bin\" and \"private.bin\"");
    }
    
    
    // Method that handles client functionality
    private static void client(String[] args) {
        String pubKeyFilename = args[1];
        String hostName = args[2];
        int port = -1;
        try {
            port = Integer.parseInt(args[3]);
        }catch(NumberFormatException e) {
            System.out.println("Last parameter for client should be an integer");
            e.printStackTrace();
            return;
        }
        
        // First generate AES session key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        Key sessionKey = keyGen.generateKey();
        
        // Encrypt session key with server's public key
        
        // Prompt user for file to transfer
        
        // Check path and ask for chunk size IN BYTES (default 1024)
        
        // Send server StartMessage with file name, length of file in bytes, chunk size, and encrypted
        // session key
        
        // Check for AckMessage, if sequence number = 0, proceed; if sequence number = -1, something's wrong
        // just quit
        
        // Loop and send each chunk of the file in order.
            // 
        
        
    } // End of client
    
    
    // Method that handles server functionality
    private static void server(String[] args) throws Exception{
        // Initializing rsa and aes ciphers, session key, crc32, and tons of stuff
        Cipher rsaCipher = Cipher.getInstance("RSA");
        Cipher aesCipher = Cipher.getInstance("AES");
        CRC32 checkCrc = new CRC32();
        int numChunks = 0, nxtSeq = -1; // -1 is a flag for an unsuccessful start message setup
        Key sessionKey = null;
        String fileName = "";
        FileOutputStream fileOut = null;
        
        String privKeyFilename = args[1];
        int port = -1;
        try {
            port = Integer.parseInt(args[2]);
        } catch(NumberFormatException e) {
            System.out.println("Second argument to server function should be an integer...");
            return;
        }
        
        // Creating server and client socket
        ServerSocket serverSocker = new ServerSocket(port);
        Socket clientSocket = serverSocker.accept();
            
        // Creating client input and output streams
        InputStream is = clientSocket.getInputStream();
        OutputStream os = clientSocket.getOutputStream();
        ObjectInputStream obIn = new ObjectInputStream(is);
        ObjectOutputStream obOut = new ObjectOutputStream(os);
        
        while(true) {    
            // Reading message from client
            Message clientMsg = (Message)obIn.readObject();
            
            if(clientMsg.getType().equals(MessageType.DISCONNECT)) {
                System.out.println("Disconnecting...");
                clientSocket.close();
                obIn.close();
                obOut.close();
                // End of if clientMsg is a DISCONNECT Message
                
            } else if(clientMsg.getType().equals(MessageType.START)) {
                StartMessage startMsg = (StartMessage) clientMsg;
                int fileSize = (int)startMsg.getSize();
                int chunkSize = (int)startMsg.getSize();
                numChunks = (int)Math.ceil((double) fileSize / (double) chunkSize);
                fileName = startMsg.getFile();
                
                try{
                    // Received client's AES key
                    byte[] clientKey = startMsg.getEncryptedKey();
                    
                    // Retrieving server private key
                    File privKeyFile = new File(privKeyFilename);
                    ObjectInputStream privKeyStream = new ObjectInputStream(new FileInputStream(privKeyFile));
                    PrivateKey privKey = (PrivateKey) privKeyStream.readObject();
                    
                    // Decrypting session key from client
                    rsaCipher.init(Cipher.UNWRAP_MODE, privKey); // Getting private key ready
                    sessionKey = rsaCipher.unwrap(clientKey, "AES", Cipher.SECRET_KEY);
                    
                    // (hopefully) successful setup so next sequence number should be 0
                    nxtSeq = 0;
                    privKeyStream.close();
                }catch(FileNotFoundException e) {
                    // Maybe private key could not be found
                    System.out.println("Private key could not be found...");
                    e.printStackTrace();
                    obOut.writeObject(new AckMessage(-1));
                    break;
                }catch(Exception e){
                    // Or anything else happened
                    System.out.println("Yeah, so something went wrong...");
                    e.printStackTrace();
                    obOut.writeObject(new AckMessage(-1));
                    break;
                }
                
                // If everything else successful,FileOutputStream can be created
                String[] temp = fileName.split("."); // Ex. test.txt -> "test" "." "txt"
                String newFilename = temp[0] + "(2)" + temp[1] + temp[2];
                fileOut = new FileOutputStream(new File(newFilename));
                
                obOut.writeObject(new AckMessage(0));
                // End of if clientMst is a START Message
                
            }else if(clientMsg.getType().equals(MessageType.STOP)) {
                System.out.println("STOP message received, stopping file transfer...");
                clientSocket.close();
                obIn.close();
                obOut.close();
                obOut.writeObject(new AckMessage(-1));
                nxtSeq = -1;
                break;
                // End of if clientMsg is a STOP message
                
            }else if(clientMsg.getType().equals(MessageType.CHUNK)) {
                Chunk clientChunk = (Chunk) clientMsg;
                // Check sequence number of chunk
                if(clientChunk.getSeq() == nxtSeq) {
                    
                    // Decrypt data using session key
                    aesCipher.init(Cipher.DECRYPT_MODE, sessionKey);
                    byte[] decData = aesCipher.doFinal(clientChunk.getData());
                    
                    // Compare CRC32 generated from data and that sent from client
                    int cliCode = clientChunk.getCrc();
                    checkCrc.update(decData);
                    
                    // If values match, store data
                    if((int)checkCrc.getValue() == cliCode) {
                        fileOut.write(decData);
                    }
                    checkCrc.reset();
                    
                    // Print status
                    System.out.printf("Chunk received [%d/%d]", clientChunk.getSeq(), numChunks);
                    
                    // Last step is to expect next sequence number and send Ack to client
                    nxtSeq++;
                    obOut.writeObject(nxtSeq);
                }
                
                if(clientChunk.getSeq() == numChunks) {
                    fileOut.close();
                    clientSocket.close();
                    System.out.println("Transfer complete");
                    break;
                }
                
            } // End of if clientMsg is a CHUNK message
            
        } // End of while loop
        
    } // End of server
    
    
 } // End of FileTranser