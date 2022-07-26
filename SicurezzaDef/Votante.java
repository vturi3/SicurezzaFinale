/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */



import java.io.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import org.bouncycastle.util.encoders.Hex;
import java.io.ByteArrayOutputStream;

import java.util.Arrays; 


/**
 *
 * @author nando
 * @time Jul 21, 2022 12:52:43 PM
 */
public class Votante {
    
    static PublicKey  PkSocietà = null;

    
    public static void setPkSocietà(PublicKey PkSocietà){
        Votante.PkSocietà = PkSocietà;
    }
    
    //func(address,voto)
    public static byte[] vote(PrivateKey privateKey, PublicKey PublicKeySocietà, String voto, PublicKey publicKey) throws Exception{
        
      
        SecureRandom random = new SecureRandom();
        byte Randomness[] = new byte[32]; 
        random.nextBytes(Randomness); 
        
        //String Randomness = new String(Hex.encode(bytes));
        System.out.println("\nRandomness votante iniziale: " + new String(Hex.encode(Randomness)));

        //qui si fa l'encrypt della randomness con la chiave pubblica del votante
        byte[] encryptedRandomness = Cryptare.encrypt(Randomness, publicKey);
        

        ByteArrayOutputStream outputStream1 = new ByteArrayOutputStream( );
        outputStream1.write( Randomness );
        outputStream1.write( voto.getBytes() );
        byte[] randVoto = outputStream1.toByteArray( );
                
        //System.out.println("\nRandomness votante + voto: " + new String(Hex.encode(randVoto)) + " " + randVoto.length);
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        
        digest.update(randVoto);
        
        byte[] hashOfRandVoto = digest.digest();
        
        //String sha256hex = new String(Hex.encode(hash));
        
        //System.out.println("\nSHA di Voto concatenato a randomness: " + Utils.toHex(hashOfRandVoto) + " " + hashOfRandVoto.length);
        /*//qui si ottiene solo la randomness, togliendo il voto concatenato precedentemente
        Randomness = Randomness.substring(0, Randomness.length()-1);*/
        
        //qui si fa l'encrypt del ciphertex che risulta essere lo SHA256(R||voto) col la public key della società
        byte[] encryptedCypherText = Cryptare.encrypt(hashOfRandVoto, PublicKeySocietà);
        //byte[] dec = Cryptare.decrypt(encryptedCypherText, PrivateKeySocietà);        
        //System.out.println("\n dec di SHA di Voto concatenato a randomness: " + Utils.toHex(dec) + " " + dec.length);

        
        ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream( );
        outputStream2.write( encryptedRandomness );
        outputStream2.write( encryptedCypherText );
        byte[] result = outputStream2.toByteArray( );
        //manda sti due fatti con la socket
        
        //System.out.println("\nMessaggio non firmed: " + new String(Hex.encode(result)));
        //System.out.println("\nMessaggio length non firmed: " + result.length);

        byte[] signature = Cryptare.signature(publicKey,privateKey, result);    

        //System.out.println("\nSignature realtive to message: " + new String(Hex.encode(signature)));
        //System.out.println("\nSignature length realtive to message: " + signature.length);    

        
        ByteArrayOutputStream outputStream3 = new ByteArrayOutputStream( );
        outputStream3.write( result );
        outputStream3.write( signature );
        /*byte[] tmp = outputStream3.toByteArray( );
        byte[] check1 = Arrays.copyOfRange(tmp, 0, 234);
        byte[] check2 = Arrays.copyOfRange(tmp, 234, 304);
        if (Arrays.equals(check1, result))
            System.out.println("bene1");
        else
            System.out.println("male1");
        if (Arrays.equals(check2, signature))
            System.out.println("bene2");
        else
            System.out.println("male2");
        Boolean ver = Cryptare.verifySignature(publicKey,check2, check1);
        System.out.println(ver);*/
        
        return outputStream3.toByteArray( );
    }
    
    
    //func(address) for 2nd part only request the randomness and resend after dec
    public static byte[] confirmVote(PrivateKey privateKey, PublicKey publicKey) throws Exception{
        byte[] encryptedMessage = null;
        byte[] possiblePublicKey = null;
        
        try{
            ObjectInputStream ois = new ObjectInputStream( new FileInputStream("ItalyChain.txt"));
            int voters = 0;
            possiblePublicKey = (byte[]) ois.readObject();
            while(Arrays.equals(possiblePublicKey,"T2-T3".getBytes()) == false){
                voters++;                
                if(Arrays.equals(possiblePublicKey, publicKey.getEncoded())){
                    //System.out.println("PK: " + Utils.toHex(publicKey.getEncoded()));
                    //System.out.println("PK: " + Utils.toHex(possiblePublicKey));
                    //System.out.println("PK: " + publicKey.getEncoded());
                    //System.out.println("PK: " + possiblePublicKey);
                    //System.out.println(Arrays.equals(possiblePublicKey, publicKey.getEncoded()));
                    byte[] tmp = (byte[]) ois.readObject();
                    encryptedMessage = Arrays.copyOfRange(tmp, 0, 234); 
                    /*encryptedRandomness = (byte[]) ois.readObject();*/
                    break;
                }else
                //System.out.println("eccoci qui");
                    ois.readObject();
                possiblePublicKey = (byte[]) ois.readObject();
            }
            /*while(voters < 2){
                voters++;
                encryptedRandomness = (byte[]) ois.readObject();
                System.out.println("PK: " + new String(Hex.encode(encryptedRandomness)));
                encryptedRandomness = (byte[]) ois.readObject();
                System.out.println("message: " + new String(Hex.encode(encryptedRandomness)));
            } */
            //System.out.println("PK: " + Utils.toHex(publicKey.getEncoded()));
            //System.out.println("PK: " + Utils.toHex(possiblePublicKey));
            //System.out.println("transaction readed from file: " + Utils.toHex(encryptedRandomness));
        }catch(Exception e){
            e.printStackTrace();
        }
        byte[] randomness = null;
        if(encryptedMessage != null){
            randomness = Cryptare.decrypt(Arrays.copyOfRange(encryptedMessage, 0, 117),privateKey);
            System.out.println("randomness ottenuta dalla chain: " + new String(Hex.encode(randomness)));
        }
               
        return randomness;
    }
}
