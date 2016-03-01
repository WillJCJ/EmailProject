/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package secureemailclient;

import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import static secureemailclient.ClientGUI.bytesToHex;
import static secureemailclient.ClientGUI.hexToBytes;

/**
 *
 * @author Will
 */
public class Message implements java.io.Serializable{
    private String sender;
    private String recipient;
    private String subject;
    private String contents;
    private String signature;
    
    public Message(){
        this.sender = "null";
        this.recipient = "null";
        this.subject = "null";
        this.contents = "null";
        this.signature = "null";
    }
    
    public Message(String sender, String recipient, String subject, String contents, String signature){
        this.sender = sender;
        this.recipient = recipient;
        this.subject = subject;
        this.contents = contents;
        this.signature = signature;
    }
    
    public Message(String sender, String recipient, String subject, String contents){
        this.sender = sender;
        this.recipient = recipient;
        this.subject = subject;
        this.contents = contents;
        this.signature = "null";
    }
    
    
    @Override
    public String toString(){
        String message =
                "To:       " + recipient + 
                "\nFrom:     " + sender + 
                "\nSubject:  " + subject +
                "\nContents: " + contents + 
                "\nSignature: " + signature;
                
        return message;
    }
    
    public String toSmallString(){
        String message =
                "\nFrom:     " + sender + 
                "\nSubject:  " + subject;
                
        return message;
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
    
    public void sign(PrivateKey privateKey){
        try {
            String s = sender + recipient + subject + contents;
            Signature instance = Signature.getInstance("SHA1withRSA");
            instance.initSign(privateKey);
            instance.update((s).getBytes());
            byte[] signatureBytes = instance.sign();
            signature = bytesToHex(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Message.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public Boolean verifySignature(PublicKey publicKey){
        try {
            byte[] signatureBytes = hexToBytes(signature);
            Signature instance = Signature.getInstance("SHA1withRSA");
            instance.initVerify((PublicKey) publicKey);
            instance.update(signatureBytes);
            boolean verified = instance.verify(signatureBytes);
            return verified;
        } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException ex) {
            Logger.getLogger(Message.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
}
