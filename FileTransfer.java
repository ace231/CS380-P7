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
                
        } else if(args[0].toLowerCase().equals("server")) {
            
            if(args.length != 3) {
                System.out.println("Incorrect number of parameters for server function detected, please try again.");
            } else {
                server(args);
            }
            
        }  else if(args[0].toLowerCase().equals("client")) {// End of if args[0] = server
            if(args.length != 4) {
                System.out.println("Incorrecto number of parameters for client function...");
            } else {
                client(args);
            }
        }
            
    } // End of main
    
    
    private static void client(String[] args) {
        
    } // End of client
    
    
    private static void server(String[] args) {
        String pubKeyFilename = args[1];
        int port;
        try {
            port = Integer.parseInt(args[2]);
        } catch(NumberFormatException e) {
            System.out.println("Second argument to server function should be an integer...");
        }
        
        ServerSocket serverSocker = new ServerSocket(port);
        
        while(true) {
            Socket clientSocket = serverSocker.accept();

        }
        
    } // End of server
    
 } // End of FileTranser