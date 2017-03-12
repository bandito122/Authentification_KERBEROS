package ServeurCle;

import GestionSocket.GestionSocket;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.DiffieHellman.DHClient;
import Network.Constants.Server_Cle_constants;
import Network.Request;
import Utils.ByteUtils;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
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
public class Exemple_ClientCle {
    public static String HOST="localhost";
    public static int PORT=6001;
    public static String KEY_TYPE="DES";
    public static String USERNAME="julien";
    public static String PWD="test";
    
    public static void main(String[] args) {
        try {
            //SC doit écouter sur le port 6001
            Socket s=new Socket(HOST, PORT);
            System.out.println("[CLIENT] connected to server: sending DH ");
            DHClient dh=new DHClient();
            GestionSocket gsocket=new GestionSocket(s);
            //envoit demande de DH avec sa partie publique
            Request r=new Request(Server_Cle_constants.DH);
            gsocket.Send(r);
            
            //envoi sa clé publique
            System.out.println("[CLIENT]Sending public key");
            r=new Request(Server_Cle_constants.DHPK);
            r.setChargeUtile(ByteUtils.toObject(dh.getPublicKey().getEncoded()));
            gsocket.Send(r);
            System.out.println("[CLIENT]Server public key received");
            
            //lit la partie publique du serveur
            r=(Request) gsocket.Receive();
            if(r.getType()==Server_Cle_constants.DHPK) {
                byte[] serverPK=ByteUtils.toByteArray((ArrayList<Byte>) r.getChargeUtile());
                dh.setPublicKey(serverPK);
            } else {
                //erreur
                System.out.printf("ERROR: received %d type!\n",r.getType());
                System.exit(-1);
            }
            
            //la DJH est fait: faut demander la clé Long Terme du serveur AS
            System.out.println("[CLIENT]Sending Get KEY ");
            r=new Request(Server_Cle_constants.GETKEY);
            r.setChargeUtile(USERNAME);
            gsocket.Send(r);
            
            //recevoir la clé
            r=(Request) gsocket.Receive();
            System.out.println("[CLIENT]Answer received");
            if(r.getType()==Server_Cle_constants.YES) {
                System.out.println("[CLIENT]Answer is yes");
                Cipher c=Cipher.getInstance("DES/ECB/PKCS5Padding");
                c.init(Cipher.DECRYPT_MODE, dh.getSecretKey());
                ArrayList<Byte> cipherKeyObject=(ArrayList<Byte>) r.getChargeUtile();
                byte[] cipherKey=ByteUtils.toByteArray(cipherKeyObject);
                byte[] plainKey=c.doFinal(cipherKey);
                Cle cle=(Cle) ByteUtils.toObject2(plainKey);
            } else {
                System.out.println("[CLIENT]Answer is no");
                System.out.printf("ERROR: received %d type!\n",r.getType());
            }
            
            //recçoit 
        } catch (IOException | InvalidParameterSpecException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | 
                NoSuchProviderException | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException | NoSuchPaddingException | ClassNotFoundException ex) {
            Logger.getLogger(Exemple_ClientCle.class.getName()).log(Level.SEVERE, null, ex);
        } catch(Exception e) {
            System.out.printf("[CLIENT]EXCEPTIONNNN : %s\n", e.getMessage());
        }
    }
}
