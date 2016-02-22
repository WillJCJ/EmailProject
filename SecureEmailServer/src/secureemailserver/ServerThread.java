package secureemailserver;

import java.io.*;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.sql.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServerThread implements Runnable{
    private String request;
    private BufferedReader inFromClient;
    private DataOutputStream outToClient;
    private Socket clientSocket;
    
//    private static final String PUBLIC_KEY_FILE = "C:\\Users\\Will\\Documents\\CS\\EmailProject\\SecureEmailServer\\keys\\public";
//    private static final String PRIVATE_KEY_FILE = "C:\\Users\\Will\\Documents\\CS\\EmailProject\\SecureEmailServer\\keys\\private";
    private static  String PUBLIC_KEY_FILE;
    private static  String PRIVATE_KEY_FILE;
    
    private Connection conn = null;
    
    private static final Random RANDOM = new SecureRandom();

    //  Database credentials
//    private static final String USER = "root";
//    private static final String PASS = "MySQL0905";
//    private static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";  
//    private static final String DB_URL = "jdbc:mysql://localhost/emaildb";

//    //  Database credentials
    private static final String USER = "spgw33";
    private static final String PASS = "fra84nce";
    private static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";  
    private static final String DB_URL = "jdbc:mysql://mysql.dur.ac.uk:3306/Pspgw33_EmailDB";
    
    public ServerThread(Socket socket){
        
        URL pubUrl = getClass().getResource("keys/public");
        URL privUrl = getClass().getResource("keys/private");
        PUBLIC_KEY_FILE = pubUrl.getPath();
        PRIVATE_KEY_FILE = privUrl.getPath();
        
        clientSocket = socket;
        try{
            inFromClient = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            outToClient = new DataOutputStream(clientSocket.getOutputStream());
        }
        catch(IOException e){
            System.err.println("Error creating input/output streams: "+e);
        }
    }
    
    public void run(){
        //Register JDBC driver
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.err.println(e);
        }
        
        String headerCode = "";
        String receivedFromClient = "";
        
        dbConnect();
        
        boolean accepted = false;
        String output = "DECLINE";
        String username;
        String encryptedPassword;
        String suppliedPassword;
        String[] parts; //split on '.' into a maximum of 2 strings
        username = "";
        
        while (true){
            try{
                request = inFromClient.readLine();
                System.out.println("Received '"+request+"' from client.");
                headerCode = request.substring(0,4);
                receivedFromClient = request.substring(4);
            }
            catch(IOException e){
                System.err.println("Error receiving from client: "+e);
                break;
            }
            //Log in
            if (headerCode.equals("LOGN")){
                suppliedPassword = "";
                parts = receivedFromClient.split("\\.",2); //split on '.' into a maximum of 3 strings
                username = parts[0];
                encryptedPassword = parts[1];
                suppliedPassword = decryptPassword(encryptedPassword);
                if (checkClientPassword(username, suppliedPassword)){
                    accepted = true;
                    System.out.println("Password accepted");
                    output = "ACCEPT";
                }
                else{
                    System.out.println("Password incorrect");
                }
            }
            //Send a message (Must have logged in)
            else if (accepted && headerCode.equals("SEND")){
                String messageTargetUser;
                String messageSignature;
                String messageContents;
                parts = receivedFromClient.split("\\.",3);
                messageTargetUser = parts[0];
                messageSignature = parts[1];
                messageContents = parts[2];
                if(addMessage(username, messageTargetUser, messageContents, messageSignature)){
                    output = "ACCEPT";
                }
            }
            //Ask for a server's public key
            else if (headerCode.equals("PUBK")){
                String pubKey = "";
                try {
                    KeyPair kp = loadKeyPair();
                    PublicKey pub = kp.getPublic();
                    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pub.getEncoded());
                    byte[] outputBytes = x509EncodedKeySpec.getEncoded();
                    pubKey = bytesToHex(outputBytes);
                } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
                    Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
                }
                output = pubKey;
            }
            //New User
            else if (headerCode.equals("NEWU")){
                parts = receivedFromClient.split("\\.",2);
                username = parts[0];
                encryptedPassword = parts[1];
                suppliedPassword = decryptPassword(encryptedPassword);
                if(addClient(username, suppliedPassword, "Change this later")){
                    output = "ACCEPT";
                }
            }
            //New Public Key for User
            else if (headerCode.equals("NKEY")){
                try {
                    byte[] encodedPublicKey = hexToBytes(receivedFromClient);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
                    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
                    if(updateClientKey(username, publicKey)){
                        output = "ACCEPT";
                    }
                } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                    Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            System.out.println("Sending '" + output + "' back.");
            writeToClient(output);
        }
    }
    
    public void writeToClient(String output){
        try {
            outToClient.writeBytes(output + "\n");
        } catch (IOException e){
            System.err.println("Error sending data to client: " + e);
        }
    }
    
    //Open a connection
    public void dbConnect(){
        try {
            System.out.println("Connecting to DB");
            conn = DriverManager.getConnection(DB_URL,USER,PASS);
            System.out.println("Connected to DB");
        } catch (SQLException e) {
            System.err.println("Failed to connect to DB: "+e);
        }
    }
    
    public ArrayList<ArrayList<String>> queryDB(String table, ArrayList<String> fields, String whereConstraint) throws SQLException{
        
        ArrayList<ArrayList<String>> results = new ArrayList<ArrayList<String>>();
        ArrayList<String> result;
        Statement st = conn.createStatement();
        String sql;
        String fieldString = "";
        for(String field : fields){
            fieldString = ", " + fieldString + field;
        }
        //remove first ", "
        fieldString = fieldString.substring(2);
        
        System.out.println("Query: " + "SELECT "+fieldString+" FROM "+table+" WHERE "+whereConstraint);
        ResultSet rs = st.executeQuery("SELECT "+fieldString+" FROM "+table+" WHERE "+whereConstraint);
        
        //Extract data from result set
        while(rs.next()){
            result = new ArrayList<String>();
            for(String field : fields){
                result.add(rs.getString(field));
            }
            results.add(result);
        }
        
        //Clean-up environment
        rs.close();
        st.close();
        //conn.close();
        return results;
    }
    
    public void addToDB(String table, String columns, String values) throws SQLException{
        Statement st = conn.createStatement();
        System.out.println("Query: " + "INSERT INTO "+table+" ("+columns+") VALUES ("+values+");");
        st.executeUpdate("INSERT INTO "+table+" ("+columns+") VALUES ("+values+");");
    }
    
    public void updateDB(String table, String updates, String whereConstraints) throws SQLException{
        Statement st = conn.createStatement();
        System.out.println("Query: " + "UPDATE "+table+" SET "+updates+" WHERE "+whereConstraints+";");
        st.executeUpdate("UPDATE "+table+" SET "+updates+" WHERE "+whereConstraints+";");
    }
    
    public boolean addMessage(String senderUser, String targetUser, String contents, String signature){
        try {
            addToDB("messages", "senderUser, targetUser, messageContents, messageSignature", "'"+senderUser+"', '"+targetUser+"', '"+contents+"', '"+signature+"'");
            return true;
        } catch (SQLException e) {
            System.err.println("Could not add message to DB: " + e);
            return false;
        }
    }
    
    public boolean addClient(String username, String password, String publicKey){
        byte[] saltBytes = getNextSalt();
        char[] passChars = password.toCharArray();
        byte[] passwordHashBytes = hash(passChars, saltBytes);
        String passwordHashString = bytesToHex(passwordHashBytes);
        String saltString = bytesToHex(saltBytes);
        try {
            addToDB("clients", "username, passwordHash, publicKey, passwordSalt", "'"+username+"', '"+passwordHashString+"', '"+publicKey+"'"+", '"+saltString+"'");
            return true;
        } catch (SQLException e) {
            System.err.println("Could not add client to DB: " + e);
            return false;
        }
    }
    
    public boolean updateClientKey(String username, PublicKey pubKey){
        String pubKeyHex = bytesToHex(pubKey.getEncoded());
        try {
            updateDB("clients", "publicKey='"+pubKeyHex+"'", "username = '"+username+"'");
            return true;
        } catch (SQLException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public ArrayList<ArrayList<String>> getClientMessages(String username){
        ArrayList<ArrayList<String>> messages = new ArrayList<ArrayList<String>>();
        ArrayList<String> fields = new ArrayList<String>();
        fields.add("senderID");
        fields.add("messageContents");
        fields.add("messageSignature");
        try {
            messages = queryDB("messages", fields, "username = "+username);
        } catch (SQLException e) {
            System.err.println("Error fetching messages from database: " + e);
        }
        return messages;
    }
    
    public String getPublicKey(String targetUser){
        ArrayList<ArrayList<String>> client = new ArrayList<ArrayList<String>>();
        ArrayList<String> fields = new ArrayList<String>();
        fields.add("publicKey");
        try {
            client = queryDB("clients", fields, "username = "+targetUser);
        } catch (SQLException e) {
            System.err.println("Error fetching key from database: " + e);
        }
        return client.get(0).get(0);
    }
    
    public String getClientSalt(String username){
        ArrayList<ArrayList<String>> client = new ArrayList<ArrayList<String>>();
        ArrayList<String> fields = new ArrayList<String>();
        fields.add("passwordSalt");
        try {
            client = queryDB("clients", fields, "username = '"+username+"'");
        } catch (SQLException e) {
            System.err.println("Error fetching salt from database: " + e);
        }
        return client.get(0).get(0);
    }
    
    public static byte[] getNextSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }
    
    public static byte[] hash(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 10000, 256);
        Arrays.fill(password, Character.MIN_VALUE);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }
    }
        
    public static boolean checkPass (String givenPassword, byte[] salt, byte[] expectedHash) {
        char[] passChars = givenPassword.toCharArray();
        byte[] checkHash = hash(passChars, salt);
        if (checkHash.length != expectedHash.length){
            return false;
        }
        for (int i = 0; i < checkHash.length; i++) {
            if (checkHash[i] != expectedHash[i]){
                return false;
            }
        }
        return true;
    }
    
    public boolean checkClientPassword(String username, String givenPassword){
        ArrayList<String> fields = new ArrayList<String>();
        ArrayList<String> user = new ArrayList<String>();
        fields.add("passwordHash");
        try {
            user = queryDB("clients", fields, "username = '"+username + "'").get(0);
        }catch (SQLException e) {
            System.err.println("Could not check password: " + e);
            return false;
        }catch (Exception e) {
            System.err.println("Username does not exist: " + e);
            return false;
        }
        System.out.println(user);
        String realPasswordHash = user.get(0);
        return checkPass(givenPassword, hexToBytes(getClientSalt(username)), hexToBytes(realPasswordHash));
    }
    
    public KeyPair genKeyPair() throws NoSuchAlgorithmException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair generatedKeyPair = keyGen.genKeyPair();
        return generatedKeyPair;
    }
    
    public void dumpKeyPair(KeyPair keyPair) {
		PublicKey pub = keyPair.getPublic();
		System.out.println("Public Key: " + bytesToHex(pub.getEncoded()));
 
		PrivateKey priv = keyPair.getPrivate();
		System.out.println("Private Key: " + bytesToHex(priv.getEncoded()));
    }

    public String bytesToHex(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
                result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }
    
    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    public String decryptString(byte[] inputBytes, PrivateKey privKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        String output = "";
        try {
            Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decrypt.init(Cipher.DECRYPT_MODE, privKey);
            output = new String(decrypt.doFinal(inputBytes), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        }
        return output;
    }
    
    public String decryptPassword(String encryptedPassword){
        String decryptedPassword = "";
        try {
            PrivateKey privKey = loadKeyPair().getPrivate();
            decryptedPassword = decryptString(hexToBytes(encryptedPassword), privKey);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        }
        return decryptedPassword;
    }
    public KeyPair loadKeyPair() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            // Read Public Key.
            File filePublicKey = new File(PUBLIC_KEY_FILE);
            FileInputStream fis = new FileInputStream(PUBLIC_KEY_FILE);
            byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
            fis.read(encodedPublicKey);
            fis.close();

            // Read Private Key.
            File filePrivateKey = new File(PRIVATE_KEY_FILE);
            fis = new FileInputStream(PRIVATE_KEY_FILE);
            byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
            fis.read(encodedPrivateKey);
            fis.close();

            // Generate KeyPair.
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                            encodedPublicKey);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                            encodedPrivateKey);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            return new KeyPair(publicKey, privateKey);
    }
}
