package KerberosAS;

import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.HMAC.HMAC;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Kerberos.AuthenticatorCS;
import Utils.ByteUtils;
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
    //public static String PWD="";    
    //public static String TGS_NAME="default";
    public static String TGS_NAME="echec";
    public static String ENCODING="UTF-8";
    public static String LDF_PATTERN="dd/MM/yyyy HH:00";
    
    public static String KEY_DIR=System.getProperty("user.home")+System.getProperty("file.separator")+
            "client_cle"+System.getProperty("file.separator")+"exemple_cle.key";
    
    static Cle Kc, Kctgs;
    static GestionSocket gsocket_AS;
    static Socket s;
    static Cipher cipher;
    static ArrayList<Object> paramAS;
    
    public static void main(String[] args) {
        try {
            //lire la clé utilisateur long terme, ici dans un fichier, en vrai reçue du serveur clé
            Kc=loadKey();
            cipher=Cipher.getInstance("DES/ECB/PKCS5Padding");
            s=new Socket(HOST, PORT_AS);
            gsocket_AS=new GestionSocket(s);
            System.out.printf("[CLIENT]Connected to server %s:%d\n",HOST, PORT_AS);
            
            SendFirstPacket();
            SendSecondPacket();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | 
                NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException ex) {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
            System.exit(-1);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static Cle loadKey() throws IOException, ClassNotFoundException {
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(KEY_DIR));
        Cle c=(Cle) ois.readObject();
        ois.close();
        return c;
    }

    private static void SendFirstPacket() throws NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException, NoSuchProviderException {
        //pour ne pas que le PWD passe en clair!
        SecurePasswordSha256 sp=new SecurePasswordSha256(PWD);
        
        //construit la liste des paramètres
        ArrayList<Object> parameters=new ArrayList(6);
        parameters.add(USERNAME);
        parameters.add(sp.getSalt());
        parameters.add(sp.getHashedPassword());
        parameters.add(InetAddress.getLocalHost().getHostAddress());
        parameters.add(TGS_NAME);
        parameters.add(LocalDateTime.now().format(
                DateTimeFormatter.ofPattern(LDF_PATTERN)));
        System.out.printf("[CLIENT]Local Host: %s\n",
                InetAddress.getLocalHost().getHostAddress());
        
        //pas de chiffrage au premier message, le serveur AS ne nous connaît pas encore
        
        //construire objet request
        NetworkPacket r=new NetworkPacket(KAS_CST.INIT);
        r.setChargeUtile(parameters);
        //envoyer
        gsocket_AS.Send(r);
        
        //lire la réponse
        r=(NetworkPacket) gsocket_AS.Receive();
        if(r.getType()==KAS_CST.YES) {
            //OK
            System.out.printf("[CLIENT]User %s connecté!\n",USERNAME);
            cipher.init(Cipher.DECRYPT_MODE, ((CleDES)Kc).getCle( ));
            paramAS=(ArrayList<Object>) r.getChargeUtile();
            ArrayList<byte[]> firstPartAS=(ArrayList<byte[]>) paramAS.get(0);
            ArrayList<byte[]> secondPartAS=(ArrayList<byte[]>) paramAS.get(1);
            
            //première partie
            Kctgs=(Cle) ByteUtils.toObject(cipher.doFinal(firstPartAS.get(0)));
            ByteBuffer bb=ByteBuffer.allocate(4);
            int version=ByteBuffer.wrap(cipher.doFinal(firstPartAS.get(1))).getInt();
            String tgServerAddr=new String(cipher.doFinal(firstPartAS.get(2)), ENCODING);            
            
            //quitter la connexion au KerberosAS
            r.setType(KAS_CST.QUIT);
            r.setChargeUtile("");
            gsocket_AS.Send(r);
        } else {
            System.out.printf("[CLIENT]Message received: %s\n",
                    ((String)r.getChargeUtile()));
            stop();
        }
        
    }
    
    //Communication avec le TGS
    private static void SendSecondPacket() throws NoSuchAlgorithmException, 
            NoSuchProviderException, InvalidKeyException, IOException, 
            IllegalBlockSizeException, BadPaddingException, UnknownHostException, ClassNotFoundException {
        
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
        System.out.println("OKOKOKKOKOK");   
    }

    private static void stop() {
        try {
            NetworkPacket r=new NetworkPacket(KAS_CST.QUIT);
            r.setChargeUtile("");
            gsocket_AS.Send(r);
            s.close();
            System.exit(-1);
        } catch (IOException ex) {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
