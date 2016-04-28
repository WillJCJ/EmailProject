/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package secureemailclient;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;

/**
 *
 * @author willjohnson
 */
public class Main {
    public Main(){
    }
    
    public void start(){
        IPSelect ipselect = new IPSelect();
        ipselect.setVisible(true);
        wait(ipselect);
        while(true){
            LoginGUI loginGUI = new LoginGUI(ipselect.getIP());
            wait(loginGUI);
            ClientGUI clientGUI = new ClientGUI(loginGUI.getSocket(), loginGUI.getUsername(), ipselect.getIP());
            clientGUI.setVisible(true);
            System.out.println("Executed");
            wait(clientGUI);
        }
    }
    
    public static void main(String args[]) {
        Main m = new Main();
        m.start();
    }
    
    public void wait(JFrame frame){
        while (frame.isVisible()){
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}
