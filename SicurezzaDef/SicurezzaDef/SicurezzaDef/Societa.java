
import java.io.*;

import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.KeyStore;

import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Societa {
    public static void main(String[] args) throws Exception {
        PrivateKey SocietaPrivateKey = null;
        PublicKey SocietaPublicKey = null;
        try {
            /* PK e PrK da client */
            File file = new File("Societykeystore.jks");
            FileInputStream is = new FileInputStream(file);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            // Information for certificate to be generated
            String password = "mario99";
            String alias = "sslSociety";
            // getting the key
            keystore.load(is, password.toCharArray());
            SocietaPrivateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
            // Get certificate of public key
            X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
            SocietaPublicKey = cert.getPublicKey();

            // Here it prints the public key
            System.out.println("Public Key Society: ");
            System.out.println(SocietaPublicKey);
            // Here it prints the private key

        } catch (Exception e) {
            System.out.println(e);
        }
        System.out.println("Grandezza Private key: " + SocietaPrivateKey.getEncoded().length);
        TimeUnit.MILLISECONDS.sleep(60000);
        // seeAll();
        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault(); // similar to the server except
        // use SSLSocketFactory instead of SSLSocketServerFactory
        SSLSocket SocSock = (SSLSocket) sockfact.createSocket("localhost", 4000); // specify host and port
        SocSock.startHandshake();

        char esito = 'c';
        OutputStream out = SocSock.getOutputStream();
        InputStream in = SocSock.getInputStream();
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
            System.out.println(SocietaPrivateKey.getEncoded());
            System.out.println("\nPrivate Key calcolata mandata: " + SocietaPrivateKey);
            byte[] signature = Cryptare.signature(SocietaPublicKey, SocietaPrivateKey, SocietaPrivateKey.getEncoded());
            ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
            outputStream2.write(SocietaPrivateKey.getEncoded());
            outputStream2.write(signature);
            byte[] result = outputStream2.toByteArray();
            out.write(result);

            out.write(Utils.toByteArray("\n"));
            System.out.println("\nFinito: " + SocietaPrivateKey);
            TimeUnit.MILLISECONDS.sleep(7000);

            out.flush();

            esito = (char) in.read();
            System.out.println(esito);
        }
        System.out.println("finito proseguo Arrivederci");
        // int ch = 0;
        // {
        // !cSock.isClosed()
        // while(true);
        // System.out.print((char)ch);
        // TimeUnit.SECONDS.sleep(1);
        // }

        // System.out.println((char)ch);
        // SmartContract.computeFinalResult(SocietaPrivateKey,4);

    }
}