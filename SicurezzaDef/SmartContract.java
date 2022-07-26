import java.security.PrivateKey;
import java.io.*;
import java.util.*;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.PublicKey;

import java.security.NoSuchProviderException;

public class SmartContract {
    /*
     * La classe SmartContract, come suggerisce il nome, contiene le funzioni
     * necessarie alla corretta simulazione di uno SmartContract su BlockChain.
     * 
     */

    /*
     * Supponiamo che abbia la chiave privata della società come attributo
     * La chiave privata verrà passata come parametro dal Validatore cosi come il
     * quorum.
     * L'HashTable conterrà l'associazione tra chaive Pubblica del Votante e
     * Randomness
     */
    private static PrivateKey privateKeySocieta;
    private static int quorum;
    private static Hashtable<String, byte[]> votersRandomness;

    /*
     * Tale metodo calcola il risultato finale chiamanto la ObtainRandomness e la
     * obtainMessages, stampando a video il risutlato
     * 
     */
    public static void computeFinalResult(PrivateKey privateKeySocietà, int quorum) {
        SmartContract.privateKeySocieta = privateKeySocietà;
        SmartContract.quorum = quorum;
        int i = 0;
        int si = 0;
        int no = 0;
        int nullo = 0;
        obtainRandomness();
        System.out.println("randomaness fatta");
        System.out.println(votersRandomness);
        String[] voti = obtainMessages();
        System.out.println("messages fatti");
        for (i = 0; i < voti.length; i++) {
            System.out.println(voti[i]);
            if (voti[i] == "00") {
                no += 1;
            } else if (voti[i] == "11") {
                si += 1;
            } else {
                nullo += 1;
            }
        }
        if (si + no + nullo < quorum) {
            System.out.println("Il Referendum non ha raggiunto il quorum quindi è annullato");
        } else if (si == no) {
            System.out.println("Il risultato è paritario per tanto il Referendum è annullato");
        } else if (si > no) {
            System.out.println("Il Referendum è vinto dal si");
        } else {
            System.out.println("Il Referendum è vinto dal no");
        }
        return;
    }

    /*
     * Questo metodo ottiene il messaggio m = (R,E) associato ad una specifica
     * chiave pubblica e ad una specifica randomness
     * 
     */
    public static String[] obtainMessages() {
        String voti[] = new String[4];
        int i = 0;
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ItalyChain.txt"));
            byte[] read = (byte[]) ois.readObject();
            while (read != null && Arrays.equals(read, "T2-T3".getBytes()) == false) {
                System.out.println("Avanti il prossimo");
                byte[] publicKey = read;
                System.out.println("publicKey: " + publicKey);
                if (votersRandomness.containsKey(Utils.toHex(publicKey))) {
                    byte[] mSigned = (byte[]) ois.readObject();
                    byte[] m = Arrays.copyOfRange(mSigned, 0, 234);
                    System.out.println("SmartContract: pk: " + Utils.toHex(publicKey) + "m: " + Utils.toHex(m));
                    byte[] E = obtainE(m);
                    byte[] C = obtainC(E);
                    voti[i] = obtainVote(C, votersRandomness.get(Utils.toHex(publicKey)));
                } else {
                    read = (byte[]) ois.readObject();
                    System.out.println("L'utente non ha confermato il messaggio con randomness" + i);

                    voti[i] = "01";
                }
                read = (byte[]) ois.readObject();
                i++;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return voti;
    }

    // this method first obtain randomness from the file associated to the pk of the
    // client
    /*
     * Tale metodo ottiene la randomness, dal file, associata ad una specifica
     * chiave pubblica.
     */
    public static void obtainRandomness() {
        votersRandomness = new Hashtable<>();
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ItalyChain.txt"));

            byte[] read = (byte[]) ois.readObject();
            System.out.println("T2-T3: " + Utils.toHex("T2-T3".getBytes()));
            while (!Arrays.equals(read, "T2-T3".getBytes())) {
                read = (byte[]) ois.readObject();
            }
            System.out.println("T2-T3: " + Utils.toHex(read));
            int i = 0;
            byte[] publicKey = (byte[]) ois.readObject();
            while (publicKey != null) {
                i++;

                byte[] randomnessSigned = (byte[]) ois.readObject();
                byte[] randomness = Arrays.copyOfRange(randomnessSigned, 0, 32);
                votersRandomness.put(Utils.toHex(publicKey), randomness);
                System.out.println("SmartContract: pk: " + publicKey + "randomness: " + Utils.toHex(randomness));
                publicKey = (byte[]) ois.readObject();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /*
     * Questo metodo restituisce C partendo da E attraverso la decifratura con la
     * Chiave Privata della Società.
     */
    public static byte[] obtainC(byte[] E) throws NoSuchProviderException {
        byte[] C = Cryptare.decrypt(E, privateKeySocieta);
        return C;
    }

    /*
     * Questo metodo
     * restituisce la
     * E partendo
     * dal messaggio iniziale,rimuovendo,
     * tramite una split,
     * la porzione
     * di randomness cifrata
     */

    public static byte[] obtainE(byte[] m) {
        byte[] E = Arrays.copyOfRange(m, 117, 234);
        return E;
    }

    /*
     * Questo metodo ottiene il voto partendo dalla C. Conoscendo la randomness
     * calcola tutte i possibili SHA256 e ritorna il valore del voto.
     * Ricordiamo che SHA256(Randomness || Vote) è uguale a C, verrà quindi
     * effettuato questo controllo per sancire il corretto voto.
     */

    public static String obtainVote(byte[] C, byte[] randomness) throws Exception {
        int i = 0;
        String voto = "00";
        while (i < 2) {
            ByteArrayOutputStream outputStreamContract = new ByteArrayOutputStream();
            outputStreamContract.write(randomness);
            outputStreamContract.write(voto.getBytes());
            byte[] randVoto = outputStreamContract.toByteArray();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(randVoto);
            byte[] hashOfRandVoto = digest.digest();
            System.out.println("come C: " + Utils.toHex(C));
            System.out.println("come hashOfRandVoto: " + Utils.toHex(hashOfRandVoto));
            if (Arrays.equals(hashOfRandVoto, C)) {
                System.out.println("sono entrato era: " + voto);
                return voto;
            } else {
                voto = "11";
            }
            i++;
        }
        return "01";
    }

    /*
     * Tale metodo verifica la presenza del certificato di uno specifico client.
     * Tale certificato viene rilasciato solo ed esclusivamente ai Votanti di
     * conseguenza, chiunque non sia in possesso di tale certificato non ha il
     * diritto di votare
     * 
     * Da notare che l'oggetto SSLSocket viene converitot in una Standard Socket
     * cosi facendo è possibile lavorare come per le standard sockest
     * 
     */
    static Boolean checkNFT(KeyStore truststore, int IDClient, PublicKey PKVoter) throws Exception {
        String alias = "sslClient" + String.valueOf(IDClient);
        // Get certificate of public key
        X509Certificate cert = (X509Certificate) truststore.getCertificate(alias);
        if (cert == null) {
            return false;
        }
        return cert.getPublicKey().equals(PKVoter);
    }

}
