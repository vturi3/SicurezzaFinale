import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.*;
import java.net.*;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.io.FileInputStream;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

// similar to SSLServer except that the Protocol sends a BigInteger object to the Server and the Server prints them
public class SSLServerAuction implements java.io.Serializable {
    public static MessageDigest com;

    static byte[] Protocol2(Socket sSock) throws Exception {
        InputStream in = sSock.getInputStream(); // convert the socket to input stream
        byte[] preimage = new byte[16];
        try {
            ObjectInputStream objectIn;
            objectIn = new ObjectInputStream(in);
            preimage = (byte[]) objectIn.readObject();
            System.out.println("preimage from client" + " " + (preimage));
            sSock.close(); // close connection

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("session closed.");
        return preimage;
    }

    static byte[] Protocol1(
            Socket sSock)
            throws Exception {
        System.out.println("session started.");
        InputStream in = sSock.getInputStream(); // convert the socket to input stream
        byte[] hashrecv = new byte[32];
        try {
            ObjectInputStream objectIn;
            byte[] preimage = new byte[17];
            objectIn = new ObjectInputStream(in);
            hashrecv = (byte[]) objectIn.readObject();
            System.out.println("hashrecv from client" + " " + (hashrecv));
        } catch (Exception e) {
            e.printStackTrace();

        }
        System.out.println("session closed.");
        return hashrecv;
    }

    public static void main(String[] args)
            throws Exception {

        SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault(); //
        SSLServerSocket sSock;
        SSLSocket[] sslSock = new SSLSocket[2];
        sSock = (SSLServerSocket) sockfact.createServerSocket(4000); // further simplification: I assume all bidders bid
                                                                     // values from 0 to 255 // this server (Auctioneer)
                                                                     // expcets to receive from each of the two bidder:
        int min = 255, val;
        // 1. C=SHA256(r || x) where r is a 256-bit long (pseudo)random string
        //
        byte[][] hashrecv = new byte[2][32];
        byte[][] preimagerecv = new byte[2][17]; // 17 BYTES because the first byte contains the bid and the remaining
                                                 // the randomness
        for (int i = 0; i < 2; i++) {
            sslSock[i] = (SSLSocket) sSock.accept(); // accept connections
            // sSock is used to accept connection and if accepts() returns successfully it
            // returns an object sslSock that can be used to read and write with one of two
            // bidders
            //

            System.out.println("new connection\n");
            hashrecv[i] = Protocol1(sslSock[i]); // hashrecv[i] contains the commitment sent from the i-th client
        }
        // here you should handle the timing, the server and clients should wait until
        // time T2 //
        for (int i = 0; i < 2; i++) {
            preimagerecv[i] = Protocol2(sslSock[i]); // for each of the two clients the Server receives the preimage
                                                     // that contains in the first byte the bid and in the remaining the
                                                     // randomness
            com = MessageDigest.getInstance("SHA256");
            byte[] hashrecomputed = com.digest(preimagerecv[i]);
            if (Arrays.equals(hashrecv[i], hashrecomputed) != true)
                System.out.println("Participant no. " + i + " communicated invalid preimage");
            val = preimagerecv[i][0];
            if (val < min)
                min = val;
        }
        System.out.println("miniimum bid: " + min);
    }
}
