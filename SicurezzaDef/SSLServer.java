import java.io.*;
import java.net.Socket;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.util.concurrent.TimeUnit;

import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.KeyStore;

import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

public class SSLServer {
    public static String s = "Server";

    // LASCXIATA SUL VALIDATORE
    static Boolean ProtocolWriteOnChain(byte[] transaction, PublicKey VoterPK) throws Exception {
        File file1 = new File("ItalyChain.txt");

        // Checks if file1 exists
        if (file1.exists() && !file1.isDirectory()) {
            // System.out.println(file1 + " Exists");
            try {
                AppendingObjectOutputStream outputStreamExist = new AppendingObjectOutputStream(
                        new FileOutputStream("ItalyChain.txt", true));
                outputStreamExist.writeObject(VoterPK.getEncoded());
                outputStreamExist.writeObject(transaction);
                // System.out.println("PK: " + Utils.toHex(VoterPK.getEncoded()) + "transaction
                // written to file" + " " + Utils.toHex(transaction));
            } catch (Exception e) {
                e.printStackTrace();
            }

        } else {
            // System.out.println(file1 + " Does not exists");
            try {
                ObjectOutputStream outputStreamNew = new ObjectOutputStream(new FileOutputStream("ItalyChain.txt"));
                outputStreamNew.writeObject(VoterPK.getEncoded());
                outputStreamNew.writeObject(transaction);
                // System.out.println("PK: " + Utils.toHex(VoterPK.getEncoded()) + "transaction
                // written to file" + " " + Utils.toHex(transaction));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return true;
    }

    // VALIDATORE
    static byte[] ClientComunication(Socket sSock, PublicKey VoterPK) throws Exception {// note that the SSLSocket
                                                                                        // object is converted in a
                                                                                        // standard Socket object and
                                                                                        // henceforth we can work as for
                                                                                        // standard Java sockets

        System.out.println("session started.");

        InputStream in = sSock.getInputStream();

        // convert the socket to input and output stream
        // OutputStream out = sSock.getOutputStream();
        // henceforth the server can send a byte array X to the server just writing with
        // out.write(X)
        // and can read a byte c from the server with c=in.read()
        // in this specific protocol the Client first sends the string "Client" to the
        // Server and receives the string "Server" from the Server and prints it
        // The server sends back the string received to the Client, so the Server will
        // send to the Client the string "Client" and the Client prints it
        // so in the end the Client will print ServerClient
        // The protocol is stupid and serves only to demonstrate how to read and write
        // on secure sockets

        // out.write(Utils.toByteArray(s));

        byte[] message = new byte[234];

        int tmp = 0;

        /*
         * for (int i=0;(tmp = in.read()) != '\n';i++)
         * {
         * message[i] = (byte)tmp;
         * //out.write(ch);
         * System.out.println(i);
         * 
         * }
         */
        int i = 0;
        TimeUnit.MILLISECONDS.sleep(1000);
        for (i = 0; i < 234; i++) {
            tmp = in.read();
            // System.out.println(tmp);
            message[i] = (byte) tmp;
            // TimeUnit.MILLISECONDS.sleep(50);
            // out.write(ch);
        }

        int signatureLength = in.available();
        byte[] signature = new byte[signatureLength];

        for (i = 0; i < signatureLength; i++) {
            tmp = in.read();
            // System.out.println(tmp);
            signature[i] = (byte) tmp;
            TimeUnit.MILLISECONDS.sleep(50);
            // out.write(ch);
        }

        // System.out.println(i);
        TimeUnit.MILLISECONDS.sleep(50);
        // System.out.println("\nMessaggio ricevuto: " + new
        // String(Hex.encode(message)));
        // System.out.println("\nfirma ricevuta: " + new String(Hex.encode(signature)));
        Boolean verify = Cryptare.verifySignature(VoterPK, signature, message);
        if (verify != true) {
            System.out.println("\nMessaggio non firmato correttamente: ");
            return null;
        }
        String recived = new String(Hex.encode(message));
        System.out.println("\nMessaggio ricevuto: " + recived);
        // out.write('\n');
        // sSock.close(); // close connection
        System.out.println("session closed.");

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(message);
        outputStream.write(signature);
        return outputStream.toByteArray();
    }

    // VALIDATORE
    static byte[] ClientComunicationRandomness(Socket sSock, PublicKey VoterPK) throws Exception {// note that the
                                                                                                  // SSLSocket object is
                                                                                                  // converted in a
                                                                                                  // standard Socket
                                                                                                  // object and
                                                                                                  // henceforth we can
                                                                                                  // work as for
                                                                                                  // standard Java
                                                                                                  // sockets

        System.out.println("session started 2 part.");
        InputStream in = sSock.getInputStream();

        byte[] message = new byte[32];
        int tmp = 0;
        int i = 0;
        TimeUnit.MILLISECONDS.sleep(1000);
        for (i = 0; i < 32; i++) {
            tmp = in.read();
            System.out.println(tmp);
            message[i] = (byte) tmp;
            // TimeUnit.MILLISECONDS.sleep(50);
            // out.write(ch);
        }

        int signatureLength = in.available();
        byte[] signature = new byte[signatureLength];

        for (i = 0; i < signatureLength; i++) {
            tmp = in.read();
            System.out.println(tmp);
            signature[i] = (byte) tmp;
            TimeUnit.MILLISECONDS.sleep(50);
            // out.write(ch);
        }
        TimeUnit.MILLISECONDS.sleep(50);
        // System.out.println("\nMessaggio ricevuto: " + new
        // String(Hex.encode(message)));
        // System.out.println("\nfirma ricevuta: " + new String(Hex.encode(signature)));
        Boolean verify = Cryptare.verifySignature(VoterPK, signature, message);
        if (verify != true) {
            System.out.println("\nMessaggio non firmato correttamente: ");
            return null;
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(message);
        outputStream.write(signature);
        return outputStream.toByteArray();
    }

    static PrivateKey SocietyFinalComunication(Socket sSock, PublicKey SocietyPK) throws Exception {// note that the
                                                                                                    // SSLSocket object
                                                                                                    // is converted in a
                                                                                                    // standard Socket
                                                                                                    // object and
                                                                                                    // henceforth we can
                                                                                                    // work as for
                                                                                                    // standard Java
                                                                                                    // sockets

        System.out.println("session started 3 part.");
        InputStream in = sSock.getInputStream();

        byte[] message = new byte[67];
        int tmp = 0;
        int i = 0;
        TimeUnit.MILLISECONDS.sleep(1000);
        for (i = 0; i < 67; i++) {
            tmp = in.read();
            System.out.println(tmp);
            message[i] = (byte) tmp;
            // TimeUnit.MILLISECONDS.sleep(50);
            // out.write(ch);
        }

        int signatureLength = in.available();
        byte[] signature = new byte[signatureLength];
        for (i = 0; i < signatureLength; i++) {
            tmp = in.read();
            System.out.println(tmp);
            signature[i] = (byte) tmp;
            TimeUnit.MILLISECONDS.sleep(50);
            // out.write(ch);
        }
        TimeUnit.MILLISECONDS.sleep(50);
        // System.out.println("\nMessaggio ricevuto: " + new
        // String(Hex.encode(message)));
        // System.out.println("\nfirma ricevuta: " + new String(Hex.encode(signature)));
        Boolean verify = Cryptare.verifySignature(SocietyPK, signature, message);
        if (verify != true) {
            System.out.println("\nMessaggio non firmato correttamente: ");
            return null;
        }

        KeyFactory kf = KeyFactory.getInstance("EC", "BC"); // or "EC" or whatever
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(message));
        System.out.println("\nPrivate Key calcolata arrivata: " + privateKey);
        return privateKey;
    }

    static PublicKey obtainVoterPK(KeyStore truststore, int IDClient) throws Exception {// note that the SSLSocket
                                                                                        // object is converted in a
                                                                                        // standard Socket object and
                                                                                        // henceforth we can work as for
                                                                                        // standard Java sockets
        String alias = "sslClient" + String.valueOf(IDClient);
        // Get certificate of public key
        X509Certificate cert = (X509Certificate) truststore.getCertificate(alias);
        // Here it prints the public key
        // System.out.println("Public Key Client" + String.valueOf(IDClient) + ":");
        // System.out.println(Utils.toHex(cert.getPublicKey().getEncoded()));
        return cert.getPublicKey();
    }

    static PublicKey obtainSocPK(KeyStore truststore) throws Exception {// note that the SSLSocket object is converted
                                                                        // in a standard Socket object and henceforth we
                                                                        // can work as for standard Java sockets
        String alias = "sslSociety";
        // Get certificate of public key
        X509Certificate cert = (X509Certificate) truststore.getCertificate(alias);
        // Here it prints the public key
        // System.out.println("Public Key Client" + String.valueOf(IDClient) + ":");
        // System.out.println(Utils.toHex(cert.getPublicKey().getEncoded()));
        return cert.getPublicKey();
    }

    static void ConfirmTransaction(Socket cSock, String esito) throws Exception {// note that the SSLSocket object is
                                                                                 // converted in a standard Socket
                                                                                 // object and henceforth we can work as
                                                                                 // for standard Java sockets
        OutputStream out = cSock.getOutputStream();

        out.write(esito.getBytes());
        // TimeUnit.MILLISECONDS.sleep(5000);
        out.write(Utils.toByteArray("\n"));
    }

    public static void main(String[] args) throws Exception {

        KeyStore truststore = null;
        try {
            /* CLIENT PART PK */
            File file = new File("truststoreServer.jks");
            FileInputStream is = new FileInputStream(file);
            truststore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "mario99";
            // getting the key
            truststore.load(is, password.toCharArray());

        } catch (Exception e) {
            System.out.println(e);
        }

        SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault(); //
        // create a factory object to handle server connections initialized with the
        // keystore passed as argument in the commandline (see Slides)
        SSLSocket[] sslSock = new SSLSocket[5];
        PublicKey[] clientPK = new PublicKey[4];

        SSLServerSocket sSock = (SSLServerSocket) sockfact.createServerSocket(4000); // bind to port 4000
        // sSock.setNeedClientAuth(true);
        // int val;
        // 1. C=SHA256(r || x) where r is a 256-bit long (pseudo)random string
        //

        /*
         * byte[][] voto = new byte[4][1];
         * byte[][] preimagerecv = new byte[2][17]; // 17 BYTES because the first byte
         * contains the bid and the remaining
         * // the randomness
         * int tmp = 0;/*
         */
        for (int i = 0; i < 4; i++) {
            System.out.println("attendo connection\n");
            sslSock[i] = (SSLSocket) sSock.accept(); // accept connections
            System.out.println("new connection\n");
            if (truststore != null) {
                clientPK[i] = obtainVoterPK(truststore, i + 1);
                if (clientPK[i] == null) {
                    System.out.println("il client non è nel truststore del server non avverranno comunicazioni");
                    continue;
                }
                // henceforth sslSock can be used to read and write on the socket - see the
                // Protocol procedure
                // notice that from this proint the code of the Server and Client is identical -
                // both can read and write using the same oject
                // you could replace Protocol with your own protocol
                byte[] firstTransaction = ClientComunication(sslSock[i], clientPK[i]);
                Boolean correctnessFirst = false;
                if (SmartContract.checkNFT(truststore, i + 1, clientPK[i]))
                    correctnessFirst = ProtocolWriteOnChain(firstTransaction, clientPK[i]);
                System.out.println("sto per inviare");
                if (correctnessFirst) {
                    System.out.println("0");
                    ConfirmTransaction(sslSock[i], "0");
                } else
                    System.out.println("1");
                ConfirmTransaction(sslSock[i], "1");
            }
        }
        // simulate the end of T1-T2
        TimeUnit.MILLISECONDS.sleep(5000);
        // now start T2-T3 phase
        String split = "T2-T3";
        try {
            AppendingObjectOutputStream outputStreamExist = new AppendingObjectOutputStream(
                    new FileOutputStream("ItalyChain.txt", true));
            outputStreamExist.writeObject(split.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("ho scrittto split t2-t3");

        for (int i = 0; i < 4; i++) {
            sslSock[i].close();
        }
        // SSLServerSocket sSock2 = (SSLServerSocket)sockfact.createServerSocket(5001);
        // // bind to port 4000
        // this lines are just to split the two phasis in the Italy Chain for comodity
        for (int i = 0; i < 4; i++) {
            System.out.println("attendoConnessioni 2 volta");
            sslSock[i] = (SSLSocket) sSock.accept(); // accept connections
            System.out.println("okey" + i);
            byte[] secondTransaction = ClientComunicationRandomness(sslSock[i], clientPK[i]);
            Boolean correctnessSecond = false;
            if (SmartContract.checkNFT(truststore, i + 1, clientPK[i]))
                correctnessSecond = ProtocolWriteOnChain(secondTransaction, clientPK[i]);
            System.out.println("sto per inviare");
            if (correctnessSecond) {
                System.out.println("0");
                ConfirmTransaction(sslSock[i], "0");
            } else
                System.out.println("1");
            ConfirmTransaction(sslSock[i], "1");
        }

        TimeUnit.MILLISECONDS.sleep(5000);
        try {
            AppendingObjectOutputStream EOF = new AppendingObjectOutputStream(
                    new FileOutputStream("ItalyChain.txt", true));
            EOF.writeObject(null);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("ho scrittto nullo, inizio t3-t4");
        PublicKey SocietyPK = obtainSocPK(truststore);
        System.out.println("attendo connection Societa\n");
        sslSock[4] = (SSLSocket) sSock.accept();
        PrivateKey SocPrivateKey = SocietyFinalComunication(sslSock[4], SocietyPK);

        System.out.println("sto per inviare");
        System.out.println("0");
        ConfirmTransaction(sslSock[4], "0");
        SmartContract.computeFinalResult(SocPrivateKey, 4);
    }
}
