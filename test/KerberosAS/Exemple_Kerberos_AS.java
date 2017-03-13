package KerberosAS;

import GestionSocket.GestionSocket;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.HMAC.HMAC;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import Kerberos.AuthenticatorCS;
import Kerberos.TicketTGS;
import Network.Constants.KerberosAS_Constantes;
import Network.Constants.KerberosTGS_Constantes;
import Network.Request;
import Utils.ByteUtils;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
    public static String TGS_NAME="default";
    public static String ENCODING="UTF-8";
    
    public static String KEY_DIR=System.getProperty("user.home")+System.getProperty("file.separator")+
            "client_cle"+System.getProperty("file.separator")+"exemple_cle.key";
    
    static Cle cleLongTerme;
    static GestionSocket gsocket;
    static Socket s;
    static Cipher cipher;
    
    public static void main(String[] args) {
        try {
            //lire la clé utilisateur long terme, ici dans un fichier, en vrai reçue du serveur clé
            cleLongTerme=loadKey();
            cipher=Cipher.getInstance("DES/ECB/PKCS5Padding");
            s=new Socket(HOST, PORT_AS);
            gsocket=new GestionSocket(s);
            System.out.printf("[CLIENT]Connected to server %s:%d\n",HOST, PORT_AS);
            
                SendFirstPacket();
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
        parameters.add(LocalDate.now());
        System.out.printf("[CLIENT]Local Host: %s\n",
                InetAddress.getLocalHost().getHostAddress());
        
        //pas de chiffrage au premier message, le serveur AS ne nous connaît pas encore
        
        //construire objet request
        Request r=new Request(KerberosAS_Constantes.INIT);
        r.setChargeUtile(parameters);
        //envoyer
        gsocket.Send(r);
        
        //lire la réponse
        r=(Request) gsocket.Receive();
        if(r.getType()==KerberosAS_Constantes.YES) {
            //OK
            cipher.init(Cipher.DECRYPT_MODE, ((CleDES)cleLongTerme).getCle());
            ArrayList<Object> param=(ArrayList<Object>) r.getChargeUtile();
            ArrayList<byte[]> firstPart=(ArrayList<byte[]>) param.get(0);
            ArrayList<byte[]> secondPart=(ArrayList<byte[]>) param.get(1);
            
            //première partie
            Cle cleSession=(Cle) ByteUtils.toObject2(cipher.doFinal(firstPart.get(0)));
            ByteBuffer bb=ByteBuffer.allocate(4);
            int version=ByteBuffer.wrap(cipher.doFinal(firstPart.get(1))).getInt();
            String tgServerAddr=new String(cipher.doFinal(firstPart.get(2)), ENCODING);
            
            //deuxieme partie= TICKET, faut avoir le AS
            HMAC hmac=new HMAC();
            LocalDateTime now=LocalDateTime.now();
            hmac.generate(((CleDES)cleSession).getCle(), USERNAME+now.format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:00")));
            ArrayList<Object> tgsParam=new ArrayList<>(3);
            
            AuthenticatorCS acs=new AuthenticatorCS(USERNAME, LocalDateTime.now(), hmac.ToString());
            
            Request tgsReq=new Request(KerberosTGS_Constantes.INIT);
            
            //Connexion au serveur TGS
            Socket s=new Socket(HOST, PORT_TGS);
            GestionSocket gs2=new GestionSocket(s);
            
            //chiffrer l'ACS
            cipher.init(Cipher.ENCRYPT_MODE, ((CleDES)cleSession).getCle());
            tgsParam.add(cipher.doFinal(ByteUtils.toByteArray(acs))); //ACS
            //ajout des autres paramètres
            tgsParam.add(secondPart.get(0)); //tgs déjà chiffré
            tgsParam.add("default"); //nom serveur
            tgsReq.setChargeUtile(tgsParam);
                    
            gs2.Send(tgsReq);
            Request reponse2=(Request) gs2.Receive();
            cipher.init(Cipher.DECRYPT_MODE, ((CleDES)cleSession).getCle());
            param=(ArrayList<Object>) reponse2.getChargeUtile();
            //premiere partie est chiffrée par kctgs
            firstPart=(ArrayList<byte[]>) param.get(0);
            Cle kcs=(Cle) ByteUtils.toObject2(cipher.doFinal(firstPart.get(0)));
            version=ByteBuffer.wrap(cipher.doFinal(firstPart.get(1))).getInt();
            String nomServeur=new String(cipher.doFinal(firstPart.get(2)),ENCODING);
            LocalDateTime ldt=LocalDateTime.parse(
                    new String(cipher.doFinal(firstPart.get(3)), ENCODING),
                    DateTimeFormatter.ofPattern("dd/MM/yyyy HH:00"));
            
            //seconde partie par ks... on ne sait pas la déchiffrer!
            byte[] ticketBis=secondPart.get(0);
            System.out.println("OKOKOKKOKOK");
        } else {
            stop();
        }
        
    }

    private static void stop() {
        try {
            s.close();
            System.exit(-1);
        } catch (IOException ex) {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
