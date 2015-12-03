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
        String message = "";
        
        dbConnect();
        
        boolean accepted = false;
        String output;
        String username;
        String suppliedPassword;
        String actualPassword;
        String salt;
        String[] details; //split on ',' into a maximum of 2 strings
        
        while (true){
            try{
                request = inFromClient.readLine();
                System.out.println("Received '"+request+"' from client.");
                headerCode = request.substring(0,4);
                message = request.substring(4);
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
                    details = message.split(",",3); //split on ',' into a maximum of 2 strings
                    username = details[0];
                    salt = details[1];
                    suppliedPassword = details[1];
                    try{
                        actualPassword = getClientPassword(username);
                        System.out.println("Password retrieved");
                    }
                    catch(SQLException e){
                        System.err.println("Error reading database: "+e);
                        //tell client
                    }
                    if (actualPassword.equals(suppliedPassword)){
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
                    } catch (IOException e) {
                        System.out.println("Error sending data to client: "+e);
                    }  
                }
            }
        }

//        try {
//            outToClient.writeBytes(output);
//            System.out.println("Sent "+output+" back");
//        } catch (IOException e) {
//            System.out.println("Error sending data to client: "+e);
//        }
//        while (true){
//            try{
//                request = inFromClient.readLine();
//                System.out.println("Received '"+request+"' from client.");
//            }
//            catch(IOException e){
//                System.err.println("Error receiving from client: "+e);
//            }
//            if (request.equals("close")){
//                try {
//                    outToClient.writeBytes("confirmed\n"); //Let the client know you got their request to close connection
//                    clientSocket.close();
//                    break;
//                } catch (IOException e) {
//                    System.out.println("Error sending data to client: "+e);
//                }
//            }
//            else{
//                output = "?";
//                try {
//                    outToClient.writeBytes(output+"\n");
//                    System.out.println("Sent "+output+" back");
//                } catch (IOException e) {
//                    System.out.println("Error sending data to client: "+e);
//                }
//            }
//        }
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
    
    public void addMessage(int senderID, int targetID, String contents, String signature) throws SQLException{
        addToDB("messages", "senderID, targetID, messageContents, messageSignature", senderID+", "+targetID+", '"+contents+"', '"+signature+"'");
    }
    
    public void addClient(String username, String password, String publicKey) throws SQLException{
        addToDB("messages", "username, password, publicKey", "'"+username+"', '"+password+"', '"+publicKey+"'");
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
        
//    public static boolean checkPass (String givenPassword, byte[] salt, byte[] expectedHash) {
//        char[] passChars = givenPassword.toCharArray();
//        byte[] checkHash = hash(passChars, salt);
//        if (checkHash.length != expectedHash.length){
//            return false;
//        }
//        for (int i = 0; i < checkHash.length; i++) {
//            if (checkHash[i] != expectedHash[i]){
//                return false;
//            }
//        }
//        return true;
//    }
//    
//    public boolean checkClientPassword(String username, String givenPassword) throws SQLException{
//        ArrayList<String> fields = new ArrayList<String>();
//        ArrayList<String> user = new ArrayList<String>();
//        fields.add("passwordHash, passwordSalt");
//        user = queryDB("clients", fields, "username = "+username).get(0);
//        String realPasswordHash = user.get(0);
//        String salt = user.get(1);
//        return true;
//    }
}
