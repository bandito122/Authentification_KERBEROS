package ServeurCle;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.DiffieHellman.DiffieHellman;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Serializator.KeySerializator;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * @author Julien
 */
public class Exemple_ClientCle {
    public static String HOST="localhost";
    public static int PORT=6001;
    public static String KEY_TYPE="DES";
    public static String USERNAME="julien";
    public static String PWD="test";
    public static String SAVING_DIR=System.getProperty("user.home")+
            System.getProperty("file.separator")+"client_cle"+
            System.getProperty("file.separator")+"exemple_cle.key";
    
    public static void main(String[] args) {
        try {
            SecurePasswordSha256 sp=new SecurePasswordSha256(PWD);
            
            //SC doit écouter sur le port 6001
            Socket s=new Socket(HOST, PORT);
            System.out.println("[CLIENT] connected to server: sending Init ");
            DiffieHellman dh=new DiffieHellman();
            GestionSocket gsocket=new GestionSocket(s);
            
            //envoit demande de DiffieHellman avec sa partie publique
            NetworkPacket r=new NetworkPacket(SC_CST.INIT);
            r.add(SC_CST.USERNAME,USERNAME);
            r.add(SC_CST.SALT, sp.getSalt());
            r.add(SC_CST.PWD, sp.getHashedPassword());
            gsocket.Send(r);
            
            r=(NetworkPacket) gsocket.Receive();
            if(r.getType()==SC_CST.YES) {
                System.out.printf("[CLIENT]User %s is connected\n", USERNAME);
            } else {
                System.out.printf("[CLIENT]User %s is NOT connected\n",USERNAME);
            }
            
            //envoi sa clé publique
            System.out.println("[CLIENT]Sending public key");
            r=new NetworkPacket(SC_CST.DHPK);
            r.add(SC_CST.PK, dh.getPublicKey().getEncoded());
            gsocket.Send(r);
            System.out.println("[CLIENT]Server public key received");
            
            //lit la partie publique du serveur
            r=(NetworkPacket) gsocket.Receive();
            if(r.getType()==SC_CST.YES) {
                byte[] serverPK=(byte[]) r.get(SC_CST.PK);
                dh.setPublicKey(serverPK);
            } else {
                //erreur
                System.out.printf("ERROR: received %d type!\n",r.getType());
                System.exit(-1);
            }
            
            //la DJH est fait: faut demander la clé Long Terme du serveur AS
            Chiffrement chDHKey=(Chiffrement) CryptoManager.newInstance("DES");
            chDHKey.init(new CleDES(dh.getSecretKey()));
            //grâce à CipherGestionSocket la transition entre flux chiffré ou non se fait
            //simplement via un changement de type de GestionSocket
            CipherGestionSocket ciphergs=new CipherGestionSocket(s, chDHKey);
            System.out.println("[CLIENT]Sending Get KEY ");
            r=new NetworkPacket(SC_CST.GETKEY);
            r.add(SC_CST.USERNAME, USERNAME);
            ciphergs.Send(r);
            
            //recevoir la clé
            r=(NetworkPacket) ciphergs.Receive();
            System.out.println("[CLIENT]Answer received");
            if(r.getType()==SC_CST.YES) {
                System.out.println("[CLIENT]Answer is yes");
                //récupère la clé & la sauvegarde dans SAVING_DIR
                Cle cle=(Cle) r.get(SC_CST.SECRETKEY);
                KeySerializator.saveKey(SAVING_DIR, cle);
                
                //test à comparer avec le serveur_clé
                Chiffrement chLongTermKey=(Chiffrement) CryptoManager.newInstance("DES");
                chLongTermKey.init(cle);
                String ciphertext=chLongTermKey.crypte("Test nananan");
                System.out.printf("texte chiffré: %s\n", Arrays.toString(ciphertext.getBytes()));
                String plainText=chLongTermKey.decrypte(ciphertext);
                System.out.printf("text déchiffré: %s\n", Arrays.toString(plainText.getBytes()));
                System.out.printf("text déchiffré: %s\n", plainText);
            } else {
                System.out.println("[CLIENT]Answer is no");
                System.out.printf("ERROR: received %d type!\n",r.getType());
            }
        } catch (IOException | InvalidParameterSpecException | NoSuchAlgorithmException | 
                InvalidAlgorithmParameterException | NoSuchProviderException | 
                InvalidKeySpecException | InvalidKeyException ex) {
            Logger.getLogger(Exemple_ClientCle.class.getName()).log(Level.SEVERE, null, ex);
        } catch(Exception e) {
            System.out.printf("[CLIENT]EXCEPTION: %s: %s\n",e.getClass(), e.getMessage());
            Logger.getLogger(Exemple_ClientCle.class.getName()).log(Level.SEVERE, null, e);
        }
    }
}
