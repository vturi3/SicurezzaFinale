
import java.io.*;
import java.net.Socket;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.concurrent.TimeUnit;
import java.security.KeyPair;

import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.KeyStore;

import java.util.Arrays;

public class SSLClient {
    public static String s = "Client\n";

    static void Protocol(Socket cSock, byte[] firstSent) throws Exception {// note that the SSLSocket object is
                                                                           // converted in a standard Socket object and
                                                                           // henceforth we can work as for standard
                                                                           // Java sockets
        char esito = 'c';
        OutputStream out = cSock.getOutputStream();
        InputStream in = cSock.getInputStream();
        while (!String.valueOf(esito).equals("0")) {
            System.out.println("cami scusa");
            // InputStream in = cSock.getInputStream();
            // henceforth the client can send a byte array X to the server just writing with
            // out.write(X)
            // and can read a byte c from the server with c=in.read()
            // in this specific protocol the Client first sends the string "Client" to the
            // Server and receives the string "Server" from the Server and prints it
            // The server sends back the string received to the Client, so the Server will
            // send to the Client the string "Client" and the Client prints it
            // so in the end the Client will print ServerClient
            // The protocol is stupid and serves only to demonstrate how to read and write
            // on secure sockets
            System.out.println(firstSent.length);
            out.write(firstSent);
            out.write(Utils.toByteArray("\n"));
            TimeUnit.MILLISECONDS.sleep(7000);

            out.flush();

            esito = (char) in.read();
            System.out.println(esito);
        }
        System.out.println("finito proseguo");
        // int ch = 0;
        // {
        // !cSock.isClosed()
        // while(true);
        // System.out.print((char)ch);
        // TimeUnit.SECONDS.sleep(1);
        // }

        // System.out.println((char)ch);
    }

    static void seeAll() throws Exception {// note that the SSLSocket object is converted in a standard Socket object
                                           // and henceforth we can work as for standard Java sockets
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ItalyChain.txt"));
        byte[] read = (byte[]) ois.readObject();
        int i = 1;
        while (read != null) {
            if (!Arrays.equals(read, "T2-T3".getBytes())) {
                System.out.println("oggetto " + i + ": " + Utils.toHex(read));
            } else {
                System.out.println("oggetto separatore" + i + ": " + new String(Utils.toHex(read)));
            }
            read = (byte[]) ois.readObject();
            i++;
        }
    }

    public static void main(String[] args) throws Exception {

        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault(); // similar to the server except
        // use SSLSocketFactory instead of SSLSocketServerFactory
        SSLSocket cSock = (SSLSocket) sockfact.createSocket("localhost", 4000); // specify host and port
        cSock.startHandshake();

        String voto = args[1];
        PrivateKey ClientPrivatekey = null;
        PublicKey ClientPublickey = null;
        try {
            /* PK e PrK da client */
            File file = new File("Client" + args[0] + "keystore.jks");
            FileInputStream is = new FileInputStream(file);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            // Information for certificate to be generated
            String password = "mario99";
            String alias = "sslClient" + args[0];
            // getting the key
            keystore.load(is, password.toCharArray());
            ClientPrivatekey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
            // Get certificate of public key
            X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
            ClientPublickey = cert.getPublicKey();

            // Here it prints the public key
            System.out.println("Public Key Client" + args[0] + ": ");
            System.out.println(ClientPublickey);
            // Here it prints the private key

        } catch (Exception e) {
            System.out.println(e);
        }

        // System.out.println(keyPair.getPrivate());

        // we send the public key to server just to allow to server to verify the
        // messages send by voters

        /*
         * System.out.println("questa e la lunghezza in byte delle chiavi: " +
         * keyPair.getPublic().getEncoded().length);
         * 
         * Protocol(cSock, keyPair.getPublic().getEncoded());
         */
        KeyStore truststore = null;
        PublicKey SocietyPublicKey = null;
        try {
            /* CLIENT PART PK */
            File file = new File("truststoreClient" + args[0] + ".jks");
            FileInputStream is = new FileInputStream(file);
            truststore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "mario99";
            // getting the key
            truststore.load(is, password.toCharArray());
            String alias = "sslSociety";
            // Get certificate of public key
            X509Certificate cert = (X509Certificate) truststore.getCertificate(alias);
            // Here it prints the public key
            // System.out.println("Public Key Client" + String.valueOf(IDClient) + ":");
            // System.out.println(Utils.toHex(cert.getPublicKey().getEncoded()));
            SocietyPublicKey = cert.getPublicKey();

        } catch (Exception e) {
            System.out.println(e);
        }

        if (ClientPrivatekey != null && ClientPublickey != null && SocietyPublicKey != null) {
            byte[] m = Votante.vote(ClientPrivatekey, SocietyPublicKey, voto, ClientPublickey);
            Protocol(cSock, m);
            // simulate the end of T1-T2
            TimeUnit.MILLISECONDS.sleep(25000);
            // now start T2-T3 phase
            byte[] r = Votante.confirmVote(ClientPrivatekey, ClientPublickey);
            SSLSocket cSock2 = (SSLSocket) sockfact.createSocket("localhost", 4000); // specify host and port
            cSock2.startHandshake();
            byte[] signature = Cryptare.signature(ClientPublickey, ClientPrivatekey, r);
            ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
            outputStream2.write(r);
            outputStream2.write(signature);
            byte[] result = outputStream2.toByteArray();
            Protocol(cSock2, result);
            TimeUnit.MILLISECONDS.sleep(25000);
            // now start T3-T4 phase
        } else {
            System.out.println("Client" + args[0] + " le mie chiavi sono null!!!:");
        }

    }
}
