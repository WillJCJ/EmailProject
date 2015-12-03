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
    
    private String clientID;
    
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
        String suppliedPassword;
        String actualPassword;
        String salt;
        String[] parts; //split on ',' into a maximum of 2 strings
        
        while (true){
            try{
                request = inFromClient.readLine();
                System.out.println("Received '"+request+"' from client.");
                headerCode = request.substring(0,4);
                receivedFromClient = request.substring(4);
            }
            catch(IOException e){
                System.err.println("Error receiving from client: "+e);
            }
            output = "";
            username = "";
            salt = "";
            switch(headerCode){
                case "LOGN":{
                    suppliedPassword = "";
                    actualPassword = "";
                    parts = receivedFromClient.split(",",3); //split on ',' into a maximum of 3 strings
                    username = parts[0];
                    salt = parts[1];
                    suppliedPassword = parts[1];
                    if (checkClientPassword(username)){
                        accepted = true;
                        System.out.println("Password accepted");
                        output = "ACCEPT";
                    }
                    else{
                        System.out.println("Password incorrect");
                        output = "DECLINE";
                    }
                    try {
                        outToClient.writeBytes(output);
                        System.out.println("Sent "+output+" back");
                    }catch (IOException e) {
                        System.err.println("Error sending data to client: "+e);
                    }
                }
                case "SEND":{
                    int messageTargetID;
                    String messageSignature;
                    String messageContents;
                    parts = receivedFromClient.split(",",3);
                    messageTargetID = Integer.parseInt(parts[0]);
                    messageSignature = parts[1];
                    messageContents = parts[2];
                    if(addMessage(Integer.parseInt(clientID), messageTargetID, messageContents, messageSignature)){
                        output = "ACCEPT";
                    }
                    else{
                        output = "DECLINE";
                    }
                    try {
                        outToClient.writeBytes(output);
                        System.out.println("Sent "+output+" back");
                    }catch (IOException e) {
                        System.err.println("Error sending data to client: "+e);
                    }
                }
            }
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
        //remove first ,_
        fieldString = fieldString.substring(2);
        
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
//        conn.close();
        return results;
    }
    
    public void addToDB(String table, String columns, String values) throws SQLException{
        Statement st = conn.createStatement();
        
        System.out.println("Query: INSERT INTO "+table+" ("+columns+") VALUES ("+values+");");
        st.executeUpdate("INSERT INTO "+table+" ("+columns+") VALUES ("+values+");");
    }
    
    public boolean addMessage(int senderID, int targetID, String contents, String signature){
        try {
            addToDB("messages", "senderID, targetID, messageContents, messageSignature", senderID+", "+targetID+", '"+contents+"', '"+signature+"'");
            return true;
        } catch (SQLException e) {
            System.err.println("Could not add message to DB: " + e);
            return false;
        }
    }
    
    public boolean addClient(String username, String password, String publicKey){
        try {
            addToDB("messages", "username, password, publicKey", "'"+username+"', '"+password+"', '"+publicKey+"'");
            return true;
        } catch (SQLException e) {
            System.err.println("Could not add message to DB: " + e);
            return false;
        }
    }
    
    public ArrayList<ArrayList<String>> getClientMessages(){
        ArrayList<ArrayList<String>> messages = new ArrayList<ArrayList<String>>();
        ArrayList<String> fields = new ArrayList<String>();
        fields.add("senderID");
        fields.add("messageContents");
        fields.add("messageSignature");
        try {
            messages = queryDB("messages", fields, "targetID = "+clientID);
        } catch (SQLException e) {
            System.err.println("Error fetching messages from database: " + e);
        }
        return messages;
    }
    
    public ArrayList<ArrayList<String>> getPublicKey(String targetID){
        ArrayList<ArrayList<String>> clients = new ArrayList<ArrayList<String>>();
        ArrayList<String> fields = new ArrayList<String>();
        fields.add("publicKey");
        try {
            clients = queryDB("clients", fields, "clientID = "+targetID);
        } catch (SQLException e) {
            System.err.println("Error fetching messages from database: " + e);
        }
        return clients;
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
    
    public boolean checkClientPassword(String givenPassword){
        ArrayList<String> fields = new ArrayList<String>();
        ArrayList<String> user = new ArrayList<String>();
        fields.add("passwordHash, passwordSalt");
        try {
            user = queryDB("clients", fields, "clientID = "+clientID).get(0);
        } catch (SQLException e) {
            System.err.println("Could not check password: " + e);
        }
        String realPasswordHash = user.get(0);
        String salt = user.get(1);
        return true;
    }
}
