/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.security.KeyPair;
import java.security.spec.ECGenParameterSpec;
import java.security.KeyPairGenerator;
import org.bouncycastle.*;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author nando
 * @time Jul 21, 2022 12:51:32 PM
 */
public class KeyGenerator {
    
    
    public static KeyPair generateKey(String name, String surname,int code) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator key = KeyPairGenerator.getInstance("EC", "BC");
        String name1 = "secp256r1";
        key.initialize(new ECGenParameterSpec(name1));
        KeyPair keyPair = key.generateKeyPair(); 
        return keyPair;
    }
    

}
