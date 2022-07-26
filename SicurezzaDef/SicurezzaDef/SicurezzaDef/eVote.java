/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */


/**
 *
 * @author vitot
 */
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec; // generators of parameters for Elliptic Curves
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class eVote {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        
        //questa classe stiamo per eliminarla
        //stiamo davvero per eliminarla
        // TODO code application logic here
        Security.addProvider(new BouncyCastleProvider());
        System.out.println(Security.getProvider("BC"));
        String name = "secp256r1"; // type of elliptic curve, other examples secp256k1
        KeyPairGenerator key = KeyPairGenerator.getInstance("ECDH");
        
        key.initialize(new ECGenParameterSpec(name));
        KeyPair keyPair = key.generateKeyPair();
        System.out.println(keyPair.getPublic());
        KeyPairGenerator key2 = KeyPairGenerator.getInstance("ECDH");
        
        key.initialize(new ECGenParameterSpec(name));
        KeyPair keyPairSocietà = key2.generateKeyPair();
        
        
        Votante.setPkSocietà(keyPairSocietà.getPublic());
        
        Votante.vote(keyPair.getPrivate(), 0, keyPair.getPublic());
        
        
       /*
        // create a challenge
        String test = "mario";
        
        byte[] challenge = test.getBytes();

        // sign using the private key
        Signature sig = Signature.getInstance("ECDSA");
        sig.initSign(privateKey);
        sig.update(challenge);
        byte[] signature = sig.sign();
        
        
        Signature sig2 = Signature.getInstance("ECDSA");
        
        sig2.initVerify(publicKey);
        
        sig2.update(challenge);

        boolean keyPairMatches = sig2.verify(signature);      
        System.out.println(keyPairMatches);
         
         
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32]; 
        random.nextBytes(bytes); 
        
        String Randomness = new String(Hex.encode(bytes));
        Randomness = Randomness.concat("mario1");
        
        System.out.println(Randomness);
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        
        digest.update(Randomness.getBytes(StandardCharsets.UTF_8));
        
        byte[] hash = digest.digest();
        
        String sha256hex = new String(Hex.encode(hash));
        
        System.out.println(sha256hex);
        String plainText = "mario";
       
       
        Cipher iesCipher = Cipher.getInstance("ECIES");
        System.out.println(" " + iesCipher.getProvider());
        
        iesCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        
        byte cipherText[] = new byte[iesCipher.getOutputSize(plainText.getBytes().length)];
        
        int ctlength=iesCipher.update(plainText.getBytes(),0,plainText.getBytes().length,cipherText,0);
        ctlength+=iesCipher.doFinal(cipherText, ctlength);
        
        System.out.println(Utils.toString(cipherText));
        
        Cipher iesCipher2 = Cipher.getInstance("ECIES");
        
        iesCipher2.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        
        byte []plainText2=new byte[iesCipher2.getOutputSize(cipherText.length)]; 
        
        int ctlength2=iesCipher2.update(cipherText,0,ctlength,plainText2,0);
        
        ctlength2+=iesCipher2.doFinal(plainText2,ctlength2);
        
        System.out.println("decrypted plaintext: "+ Utils.toString(plainText2));*/
       
       
       
       
       
        
    }
}

