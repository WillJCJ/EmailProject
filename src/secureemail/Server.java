package secureemail;

import java.net.ServerSocket;
import java.net.Socket;

public class Server{
    
    public static void main(String[] args){
    
        try {
            create(18300);
        } catch (Exception ex) {
            System.err.println("Error creating server");
        }
    }
    
    public static void create(int port) throws Exception{     
        String request;
        ServerSocket welcomeSocket;
        Socket connectionSocket;
        welcomeSocket = new ServerSocket(port);
        System.out.println("Server created on port: "+port+".  Waiting for client");
        while(true) { 
            connectionSocket = welcomeSocket.accept();
            System.out.println("Accepted connection.  Creating new thread.");
            Thread thread = new Thread(new ServerThread(connectionSocket));
            thread.start();
        }
    }
}
