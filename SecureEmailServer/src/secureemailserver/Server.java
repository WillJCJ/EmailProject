package secureemailserver;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server{
    
//    private static final String PUBLIC_KEY_FILE = "C:\\Users\\Will\\Documents\\CS\\EmailProject\\SecureEmailServer\\keys\\public";
//    private static final String PRIVATE_KEY_FILE = "C:\\Users\\Will\\Documents\\CS\\EmailProject\\SecureEmailServer\\keys\\private";
    private static final String PUBLIC_KEY_FILE = "C:\\Users\\Will\\Documents\\CS\\EmailProject\\SecureEmailServer\\keys\\public";
    private static final String PRIVATE_KEY_FILE = "C:\\Users\\Will\\Documents\\CS\\EmailProject\\SecureEmailServer\\keys\\private";
    
    public static void main(String[] args){
    
        try {
            create(18300);
        } catch (Exception ex) {
            System.err.println("Error creating server");
        }
    }
    
    public static void create(int port) throws Exception{
        ServerSocket welcomeSocket;
        Socket connectionSocket;
        welcomeSocket = new ServerSocket(port);
        
        try {
            saveKeyPair(genKeyPair());
        } catch (IOException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("Server created on port: "+port+".  Waiting for client");
        while(true) { 
            connectionSocket = welcomeSocket.accept();
            System.out.println("Accepted connection.  Creating new thread.");
            Thread thread = new Thread(new ServerThread(connectionSocket));
            thread.start();
        }
    }
    
    public static KeyPair genKeyPair() throws NoSuchAlgorithmException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair generatedKeyPair = keyGen.genKeyPair();
        return generatedKeyPair;
    }

    public static void saveKeyPair(KeyPair keyPair) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                        publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_FILE);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                        privateKey.getEncoded());
        fos = new FileOutputStream(PRIVATE_KEY_FILE);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }
}
