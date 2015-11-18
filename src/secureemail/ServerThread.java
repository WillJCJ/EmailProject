package secureemail;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.sql.*;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerThread implements Runnable{
    private String request;
    private BufferedReader inFromClient;
    private DataOutputStream outToClient;
    private Socket clientSocket;
    
    private String clientID;
    
    private Connection conn = null;

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
        
        String output = "";
        
        dbConnect();
        
        //Login the client
        boolean accepted = false;
        String suppliedPassword = "";
        String actualPassword = "";
        while (!accepted){
            try{
                System.out.println("Waiting for request from client.");
                request = inFromClient.readLine();
                String[] details = request.split(",");
                clientID = details[0];
                suppliedPassword = details[1];
                System.out.println("Received:");
                System.out.println("clientID: " + clientID);
                System.out.println("Password: " + suppliedPassword);
            }
            catch(IOException e){
                System.err.println("Error receiving from client: "+e);
            }
            try{
                actualPassword = getClientPassword();
                System.out.println("Password retrieved");
            }
            catch(SQLException e){
                System.err.println("Error reading database: "+e);
                //tell client
            }
            if (actualPassword.equals(suppliedPassword)){
                accepted = true;
                System.out.println("Password accepted");
                output = "accepted";
            }
            else{
                System.out.println("Password incorrect");
                output = "Please re-enter password";
                try {
                    outToClient.writeBytes(output);
                    System.out.println("Sent "+output+" back");
                } catch (IOException e) {
                    System.out.println("Error sending data to client: "+e);
                }
            }
        }
        try {
            outToClient.writeBytes(output);
            System.out.println("Sent "+output+" back");
        } catch (IOException e) {
            System.out.println("Error sending data to client: "+e);
        }
        while (true){
            try{
                request = inFromClient.readLine();
                System.out.println("Received '"+request+"' from client.");
            }
            catch(IOException e){
                System.err.println("Error receiving from client: "+e);
            }
            if (request.equals("close")){
                try {
                    outToClient.writeBytes("confirmed\n"); //Let the client know you got their request to close connection
                    clientSocket.close();
                    break;
                } catch (IOException e) {
                    System.out.println("Error sending data to client: "+e);
                }
            }
            else{
                output = "?";
                try {
                    outToClient.writeBytes(output+"\n");
                    System.out.println("Sent "+output+" back");
                } catch (IOException e) {
                    System.out.println("Error sending data to client: "+e);
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
            System.err.println(e);
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
        
        System.out.println("Query: SELECT "+fieldString+" FROM "+table+" WHERE "+whereConstraint);
        
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
        conn.close();
        return results;
    }
    
    public String getClientPassword() throws SQLException{
        String password;
        ArrayList<String> fields = new ArrayList<String>();
        fields.add("password");
        password = queryDB("clients", fields, "clientID = "+clientID).get(0).get(0);
        return password;
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
}
