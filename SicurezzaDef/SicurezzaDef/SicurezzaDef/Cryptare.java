/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */



import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.*;
import java.security.NoSuchProviderException;
import java.util.Arrays; 
/**
 *
 * @author nando
 * @time Jul 21, 2022 12:51:23 PM
 */
public class Cryptare {
    
    //byte[] address,
    public static byte[] signature(PublicKey publicKey,  PrivateKey privateKey, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException{ 
        
        // sign using the private key
        Security.addProvider(new BouncyCastleProvider());
        Signature sig = Signature.getInstance("ECDSA", "BC");
        sig.initSign(privateKey);
        sig.update(message);
        byte[] signature = sig.sign();
        
        return signature;
    }
    
    public static Boolean verifySignature(PublicKey publicKey, byte[] signature, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,NoSuchProviderException{ 
        
        Security.addProvider(new BouncyCastleProvider());
        Signature sig = Signature.getInstance("ECDSA", "BC");
        // verify signature using the public key
        sig.initVerify(publicKey);
        sig.update(message);

        boolean keyPairMatches = sig.verify(signature);    
        
        return keyPairMatches;
        
    }  
    
    public static byte[] encrypt(byte[] message , PublicKey publicKey) throws NoSuchProviderException{
        
        byte cipherText[] = null;
       
        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher iesCipher = Cipher.getInstance("ECIES", "BC");
            
            iesCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            
            cipherText = new byte[iesCipher.getOutputSize(message.length)];
            
            int ctlength=iesCipher.update(message,0,message.length,cipherText,0);
            ctlength+=iesCipher.doFinal(cipherText, ctlength);
            System.out.println(ctlength);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ShortBufferException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cipherText;
        
    }
    
    public static byte[] decrypt(byte cipherText[], PrivateKey privateKey) throws NoSuchProviderException{
        
        byte []plainText = null;
        
        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher iesCipher2 = Cipher.getInstance("ECIES", "BC");
            
            iesCipher2.init(Cipher.DECRYPT_MODE, privateKey);
            
            plainText=new byte[iesCipher2.getOutputSize(cipherText.length)];
            System.out.println(cipherText.length);
            int ctlength2=iesCipher2.update(cipherText,0,cipherText.length,plainText,0);
            
            ctlength2+=iesCipher2.doFinal(plainText,ctlength2);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ShortBufferException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Cryptare.class.getName()).log(Level.SEVERE, null, ex);
        }
         
        return Arrays.copyOfRange(plainText, 0, plainText.length-1);
    }
    
    
    
    
    



}
