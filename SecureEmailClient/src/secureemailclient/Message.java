/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package secureemailclient;

import java.security.*;
import java.security.spec.*;
import java.util.logging.*;

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
    private String signedPart;
    private boolean verified;
    
    public Message(){
        this.sender = "null";
        this.recipient = "null";
        this.subject = "null";
        this.contents = "null";
        this.signature = "null";
        this.signedPart = "null";
        this.verified = false;
    }
    
    public Message(String sender, String recipient, String subject, String contents, String signature){
        this.sender = sender;
        this.recipient = recipient;
        this.subject = subject;
        this.contents = contents;
        this.signature = signature;
        this.signedPart = sender + recipient + subject + contents;
        this.verified = false;
    }
    
    public Message(String sender, String recipient, String subject, String contents){
        this.sender = sender;
        this.recipient = recipient;
        this.subject = subject;
        this.contents = contents;
        this.signature = "null";
        this.signedPart = sender + recipient + subject + contents;
        this.verified = false;
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
                "From:     " + sender +
                "\nSubject:  " + subject;
                
        return message;
    }
    
    public String displayHTMLString(){
        if (verified){
            return "<html><font color=\"black\">Sender:  " + sender + "<br/>"
                        + "Subject: " + subject + "</font></html>";
        }
        else{
            return "<html><font color=\"red\">Sender:  " + sender + "<br/>"
                        + "Subject: " + subject + "</font></html>";
        }
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
    
    public boolean isVerified(){
        return verified;
    }
    
    public void setVerified(boolean value){
        verified = value;
    }
    
    public void sign(PrivateKey privateKey){
        try {
            Signature instance = Signature.getInstance("SHA1withRSA");
            instance.initSign(privateKey);
            instance.update(contents.getBytes());
            byte[] signatureBytes = instance.sign();
            signature = bytesToHex(signatureBytes);
        } catch (InvalidKeyException e){
            System.err.println("Error signing string, key invalid");
        } catch (NoSuchAlgorithmException | SignatureException e) {
            System.err.println("Error signing string: "+e);
        }
    }
    
    public Boolean verifySignature(PublicKey publicKey){
        try {
            byte[] signatureBytes = hexToBytes(signature);
            Signature instance = Signature.getInstance("SHA1withRSA");
            instance.initVerify((PublicKey) publicKey);
            instance.update(contents.getBytes());
            return instance.verify(signatureBytes);
        } catch (InvalidKeyException e){
            System.err.println("Error signing string, key invalid");
        } catch (NoSuchAlgorithmException | SignatureException e) {
            System.err.println("Error signing string: "+e);
        }
        return false;
    }
    
    public Boolean verifySignature(String hexKey){
        try {
            PublicKey publicKey = hexToPublicKey(hexKey);
            return verifySignature(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(Message.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public static String bytesToHex(byte[] b) {
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
    
    public PublicKey hexToPublicKey(String hexKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
        byte[] encodedPublicKey = hexToBytes(hexKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        return keyFactory.generatePublic(publicKeySpec);
    }
}
