import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.*;
import java.net.*;
import java.math.BigInteger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.KeyStore;

public class SSLClientAuction implements java.io.Serializable {
    public static MessageDigest com;

    /*
     * static SSLContext createSSLContext(String store, String alias) // this method
     * is not used - we leave it in case it
     * // is needed for some test...
     * throws Exception {
     * KeyManagerFactory keyFact = KeyManagerFactory.getInstance("SunX509");
     * KeyStore clientStore = KeyStore.getInstance("JKS");
     * clientStore.load(new FileInputStream(store), "changeit".toCharArray());
     * keyFact.init(clientStore, "changeit".toCharArray());
     * 
     * SSLContext sslContext = SSLContext.getInstance("TLS");
     * sslContext.init(new X509KeyManager[] { new MyKeyManager(store,
     * "changeit".toCharArray(), alias)
     * }, null, null); // sslContext.init(keyFact.getKeyManagers(), null, null);
     * return sslContext;
     * }
     */

    static void Protocol3(byte[] preimage) throws Exception {
        try {
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("MDandJ.txt"));

            outputStream.writeObject(preimage);
            System.out.println("preimage written to file" + " " + (preimage));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void Protocol2(
            Socket cSock, byte[] preimage) throws Exception

    {
        OutputStream out = cSock.getOutputStream();
        try {
            ObjectOutputStream outputStream;
            outputStream = new ObjectOutputStream(out);
            outputStream.writeObject(preimage);
            System.out.println("preimagesent to server" + " " + (preimage));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void Protocol1(
            Socket cSock, byte[] preimage) throws Exception {
        OutputStream out = cSock.getOutputStream();
        try {

            byte[] hashsent = new byte[32];
            ObjectOutputStream outputStream;
            com = MessageDigest.getInstance("SHA256"); // com is a SHA256 object hashsent=com.digest(preimage); //
                                                       // hashsent=SHA256(preimage)

            outputStream = new ObjectOutputStream(out);

            outputStream = new ObjectOutputStream(out);
            outputStream.writeObject(hashsent); // send hashsent to the Server System.out.println("hashsent to server"+"
                                                // "+Utils.toHex(hashsent));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main( // the client is the bidder and takes from command line the bid (that is for
                             // simplicity an integer from 0 to 255)

            String[] args)
            throws Exception {
        
        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket cSock = (SSLSocket) sockfact.createSocket("localhost", 4000);
        cSock.startHandshake(); // connects to the Auctioneer that is listening on port 4000
        
        byte[] preimage = new byte[17]; // client has to compute a preimage (r) that is the XOR of two random strings
                                        // preimage1 (r1) and preimage2 (r2)
        byte[] preimage1 = new byte[17];
        byte[] preimage2 = new byte[17];
        // the arrays are of length 17 because I put in the first byte the bid and the
        // remaining 16 bytes are the randomness
        SecureRandom r = new SecureRandom();
        r.nextBytes(preimage1); // fills preimage1 with random bytes
        r.nextBytes(preimage2); // fills preimage2 with random bytes

        for (int i = 0; i < preimage.length; i++)
            preimage[i] = (byte) (preimage1[i] ^ preimage2[i]); // preimage= preimage1 XOR preimage2
        preimage[0] = (byte) Integer.parseInt("2"); // put the bid taken from command line in preimage[0] // at this
                                                        // point preimage has bid in first byte followed by 16 random
                                                        // bytes
        Protocol1(cSock, preimage); // this protocol sends to the server (Auctioneer) the hash of the array preimage
        Protocol3(preimage1); // this simulates the fact that the bidder sends Enc(PKMD, CertB || Sig(SKB,r1))
                              // to the blockchain
        // we simulate this with write to file. In this program for simplicity we just
        // write r1 in the clear and we see how to encrypt the full data in other
        // example.
        // and also you should add anoter protocol that writes on a file Enc(PKJ,r2)
        TimeUnit.SECONDS.sleep(4); // this sleep is to model the wait until time T2
        Protocol2(cSock, preimage); // this protocol takes as input the array preimage (that also contains the bid)
                                    // and sends it to the Server. In the project example the opening is done
        // with an encryption under the Auctioneer's PK. Here we do not encrypt since we
        // are using TLS to communicate with the Auctioneer
        cSock.close();
    }
}