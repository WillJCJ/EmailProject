/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package secureemailclient;

import java.security.*;

/**
 *
 * @author Will
 */
public class Message {
    private String sender;
    private String recipient;
    private String subject;
    private String contents;
    private String signature;
    
    public Message(String sender, String recipient, String subject, String contents, String signature){
        this.sender = sender;
        this.sender = recipient;
        this.sender = subject;
        this.contents = contents;
        this.sender = signature;
    }
    
    public String getSender(){
        return sender;
    }
    
    public String getRecipient(){
        return recipient;
    }
    
    public String getSubject(){
        return subject;
    }
    
    public String getContents(){
        return contents;
    }
    
    public String getSignature(){
        return signature;
    }
    
    public void sign(PrivateKey privKey){
        
    }
    public void verifySignature(PublicKey pubKey){
        
    }
}
