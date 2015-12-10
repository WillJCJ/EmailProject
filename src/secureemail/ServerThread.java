package secureemail;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class ServerThread implements Runnable{
    private String request;
    private BufferedReader inFromClient;
    private DataOutputStream outToClient;
    private Socket clientSocket;
    
    private Connection conn = null;
    
    private static final Random RANDOM = new SecureRandom();

    //  Database credentials
    private static final String USER = "root";
    private static final String PASS = "MySQL0905";
    private static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";  
    private static final String DB_URL = "jdbc:mysql://localhost/emaildb";
    
    public ServerThread(Socket socket){
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
        String output;
        String username;
        String suppliedPasswordHash;
        String actualPasswordHash;
        String salt;
        String[] parts; //split on '.' into a maximum of 2 strings
        username = "";
        salt = "";
        
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
                suppliedPasswordHash = "";
                parts = receivedFromClient.split("\\.",2); //split on '.' into a maximum of 3 strings
                username = parts[0];
                suppliedPasswordHash = parts[1];
                if (checkClientPassword(username, suppliedPasswordHash)){
                    accepted = true;
                    System.out.println("Password accepted");
                    output = "ACCEPT";
                }
                else{
                    System.out.println("Password incorrect");
                    output = "DECLINE";
                }
            }
            //Send a message (Must have logged in)
            else if (accepted && headerCode.equals("SEND")){
                String messageTargetUser;
                String messageSignature;
                String messageContents;
                parts = receivedFromClient.split("\\.",3);
                messageTargetUser = parts[0];
                //messageSignature = parts[1];
                messageContents = parts[1];
                if(addMessage(username, messageTargetUser, messageContents, "sig")){
                    output = "ACCEPT";
                }
                else{
                    output = "DECLINE";
                }
            }
            //Ask for a client's salt
            else if (headerCode.equals("SALT")){
                output = getClientSalt(receivedFromClient);
            }
            //New Salt
            else if (headerCode.equals("NEWS")){
                salt = Arrays.toString(getNextSalt());
                output = salt;
            }
            //New User
            else if (headerCode.equals("NEWU")){
                System.out.println(receivedFromClient);
                parts = receivedFromClient.split("\\.",2);
                System.out.println(parts);
                username = parts[0];
                suppliedPasswordHash = parts[1];
                System.out.println(username+":::"+suppliedPasswordHash);
                addClient(username, suppliedPasswordHash, "Change this later", salt);
                output = "ACCEPT";
            }
            else{
                output = "DECLINE";
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
    
    public boolean addMessage(String senderUser, String targetUser, String contents, String signature){
        try {
            addToDB("messages", "senderUser, targetUser, messageContents, messageSignature", "'"+senderUser+"', '"+targetUser+"', '"+contents+"', '"+signature+"'");
            return true;
        } catch (SQLException e) {
            System.err.println("Could not add message to DB: " + e);
            return false;
        }
    }
    
    public boolean addClient(String username, String passwordHash, String publicKey, String passwordSalt){
        try {
            addToDB("clients", "username, passwordHash, publicKey, passwordSalt", "'"+username+"', '"+passwordHash+"', '"+publicKey+"'"+", '"+passwordSalt+"'");
            return true;
        } catch (SQLException e) {
            System.err.println("Could not add message to DB: " + e);
            return false;
        }
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
    
    public boolean checkClientPassword(String username, String givenPasswordHash){
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
        if (realPasswordHash.equals(givenPasswordHash)){
            return true;
        }
        else{
            return false;
        }
    }
}
