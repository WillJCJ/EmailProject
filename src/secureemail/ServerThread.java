package secureemail;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
public class ServerThread implements Runnable{
    private String request;
    private BufferedReader inFromClient;
    private DataOutputStream outToClient;
    private Socket clientSocket;
    
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
        String ip;
        int port;
        String output = "";
        while (output.equals("close")){
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
}
