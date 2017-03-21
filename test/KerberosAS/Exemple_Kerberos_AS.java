package KerberosAS;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.HMAC.HMAC;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Kerberos.AuthenticatorCS;
import JavaLibrary.Utils.ByteUtils;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import Kerberos.KAS_CST;
import Kerberos.KTGS_CST;
import java.util.Arrays;

/*
 * @author Julien
 */
public class Exemple_Kerberos_AS {
    public static String HOST="localhost";
    public static int PORT_AS=6002;
    public static int PORT_TGS=6003;
    public static String KEY_TYPE="DES";
    public static String USERNAME="julien";
    public static String PWD="test";    
    //public static String PWD=""; //debug
    public static String TGS_NAME="default";
    //public static String TGS_NAME="echec"; //debug
    
    //à mettre dans configuration     
    public static String ENCODING="UTF-8";
    public static String LDF_PATTERN="dd/MM/yyyy HH:00";
    public static String ALGORITHM="DES";
    
    public static String KEY_DIR=System.getProperty("user.home")+System.getProperty("file.separator")+
            "client_cle"+System.getProperty("file.separator")+"exemple_cle.key";
    
    static Chiffrement chKc, chKctgs;
    static Cle Kc, Kctgs;
    static GestionSocket gsocket_AS;
    static Socket s;
    static Cipher cipher;
    static NetworkPacket paramAS;
    
    public static void main(String[] args) {
        try {
            //lire la clé utilisateur long terme, ici dans un fichier, en vrai reçue du serveur clé
            Kc=loadKey();
            chKctgs=(Chiffrement) CryptoManager.newInstance(ALGORITHM);
            chKc=(Chiffrement) CryptoManager.newInstance(ALGORITHM);
//            cipher=Cipher.getInstance("DES/ECB/PKCS5Padding");
            s=new Socket(HOST, PORT_AS);
            gsocket_AS=new GestionSocket(s);
            System.out.printf("[CLIENT]Connected to server %s:%d\n",HOST, PORT_AS);
            
            //test KerberosAS
            SendFirstPacket();
            //test KerberosTGS
            SendSecondPacket();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | 
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
            System.exit(-1);
        } catch (NoSuchProviderException | NoSuchChiffrementException ex) {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static Cle loadKey() throws IOException, ClassNotFoundException {
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(KEY_DIR));
        Cle c=(Cle) ois.readObject();
        ois.close();
        return c;
    }

    private static void SendFirstPacket() throws NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException, NoSuchProviderException, NoSuchChiffrementException {
        //pour ne pas que le PWD passe en clair!
        SecurePasswordSha256 sp=new SecurePasswordSha256(PWD);
        
        //construit la liste des paramètres et envoyer
        NetworkPacket np=new NetworkPacket(KAS_CST.INIT);
        np.add(KAS_CST.USERNAME, USERNAME);
        np.add(KAS_CST.SALT, sp.getSalt());
        np.add(KAS_CST.PWD, sp.getHashedPassword());
        np.add(KAS_CST.INTERFACE, InetAddress.getLocalHost().getHostAddress());
        np.add(KAS_CST.TGSNAME, TGS_NAME);
        np.add(KAS_CST.DATETIME, LocalDateTime.now().format(
                DateTimeFormatter.ofPattern(LDF_PATTERN)));
        System.out.printf("[CLIENT]Local Host: %s\n",
                InetAddress.getLocalHost().getHostAddress());
        gsocket_AS.Send(np);
        
        //lire la réponse. de +, on est en partiellement chiffré donc pas de CipherGestionSocket
        paramAS=(NetworkPacket) gsocket_AS.Receive();
        //permet également de déchiffrer
        CipherGestionSocket cgs=new CipherGestionSocket(null, chKc);
        if(paramAS.getType()==KAS_CST.YES) {
            //OK
            System.out.printf("[CLIENT]User %s connecté!\n",USERNAME);
            //cipher.init(Cipher.DECRYPT_MODE, ((CleDES)Kc).getCle( ));
            chKc.init(Kc);
            /*paramAS=(ArrayList<Object>) r.getChargeUtile();
            ArrayList<byte[]> firstPartAS=(ArrayList<byte[]>) paramAS.get(0);
            ArrayList<byte[]> secondPartAS=(ArrayList<byte[]>) paramAS.get(1);*/
            
            //première partie
            //Kctgs=(Cle) ByteUtils.toObject(cipher.doFinal(firstPartAS.get(0)));
        //Kctgs=(Cle) ByteUtils.toObject(chKc.decrypte((byte[])paramAS.get(KAS_CST.KCTGS)));
            Kctgs=(Cle) ByteUtils.toObject(cgs.decrypte(paramAS.get(KAS_CST.KCTGS)));
            /*ByteBuffer bb=ByteBuffer.allocate(4);
            int version=ByteBuffer.wrap(cipher.doFinal(firstPartAS.get(1))).getInt();*/
            int version=(Integer) ByteUtils.toObject(cgs.decrypte(paramAS.get(KAS_CST.VERSION)));
            //String tgServerAddr=new String(cipher.doFinal(firstPartAS.get(2)), ENCODING);            
            String tgServerAddr=(String) ByteUtils.toObject(cgs.decrypte(paramAS.get(KAS_CST.TGSNAME)));;
             
            //afficher
            System.out.printf("[CLIENT]KerberosAS est de version %d, le nom du TGS est: %s\n", 
                    version,tgServerAddr);
            //quitter la connexion au KerberosAS
            NetworkPacket response=new NetworkPacket(KAS_CST.QUIT);
            gsocket_AS.Send(response);
            
            //test
            Chiffrement chKctgs=(Chiffrement) CryptoManager.newInstance(ALGORITHM);
            chKctgs.init(Kctgs);
            String ciphertext=chKctgs.crypte("Charbon");
            System.out.printf("texte chiffré: %s\n", Arrays.toString(ciphertext.getBytes()));
            String plainText=chKctgs.decrypte(ciphertext);
            System.out.printf("text déchiffré: %s\n", Arrays.toString(plainText.getBytes()));
            System.out.printf("text déchiffré: %s\n", plainText);
        } else { //pas ok
            System.out.printf("[CLIENT]Message received: %s\n",
                    ((String)paramAS.get(KAS_CST.MSG)));
            stop();
        }
        
    }
    
    //Communication avec le TGS
    private static void SendSecondPacket() throws NoSuchAlgorithmException, 
            NoSuchProviderException, InvalidKeyException, IOException, 
            IllegalBlockSizeException, BadPaddingException, UnknownHostException, ClassNotFoundException {
        /*
        ArrayList<byte[]> firstPartAS=(ArrayList<byte[]>) paramAS.get(0);
        ArrayList<byte[]> secondPartAS=(ArrayList<byte[]>) paramAS.get(1);
        
     //deuxieme partie= TICKET, faut avoir le AS
        HMAC hmac=new HMAC();
        LocalDateTime now=LocalDateTime.now();
        hmac.generate(((CleDES)Kctgs).getCle(), USERNAME+now.format(
                DateTimeFormatter.ofPattern(LDF_PATTERN)));
        ArrayList<Object> tgsParam=new ArrayList<>(3);

        AuthenticatorCS acs=new AuthenticatorCS(USERNAME, 
                LocalDateTime.now(), hmac.ToString());

        NetworkPacket tgsReq=new NetworkPacket(KTGS_CST.INIT);

        //Connexion au serveur TGS
        Socket s=new Socket(HOST, PORT_TGS);
        GestionSocket gsocket_TGS=new GestionSocket(s);

        //chiffrer l'ACS
        cipher.init(Cipher.ENCRYPT_MODE, ((CleDES)Kctgs).getCle());
        tgsParam.add(cipher.doFinal(ByteUtils.toByteArray(acs))); //ACS
        
        //ajout des autres paramètres
        tgsParam.add(secondPartAS.get(0)); //tgs déjà chiffré
        tgsParam.add("default"); //nom serveur
        tgsReq.setChargeUtile(tgsParam);

        gsocket_TGS.Send(tgsReq);
        NetworkPacket reponse2=(NetworkPacket) gsocket_TGS.Receive();
        cipher.init(Cipher.DECRYPT_MODE, ((CleDES)Kctgs).getCle());
        paramAS=(ArrayList<Object>) reponse2.getChargeUtile();
        
        //premiere partie est chiffrée par kctgs
        firstPartAS=(ArrayList<byte[]>) paramAS.get(0);
        Cle kcs=(Cle) ByteUtils.toObject(cipher.doFinal(
                firstPartAS.get(0)));
        int version=ByteBuffer.wrap(
                cipher.doFinal(firstPartAS.get(1))).getInt();
        String nomServeur=new String(cipher.doFinal(firstPartAS.get(2)),
                ENCODING);
        LocalDateTime ldt=LocalDateTime.parse(
                new String(cipher.doFinal(firstPartAS.get(3)), ENCODING),
                DateTimeFormatter.ofPattern(LDF_PATTERN));

        //seconde partie par ks... on ne sait pas la déchiffrer!
        byte[] ticketBis=secondPartAS.get(0);
        System.out.println("OKOKOKKOKOK");   */
    }

    private static void stop() {
        try {
            NetworkPacket r=new NetworkPacket(KAS_CST.QUIT);
            //r.setChargeUtile("");
            gsocket_AS.Send(r);
            s.close();
            System.exit(-1);
        } catch (IOException ex) {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
