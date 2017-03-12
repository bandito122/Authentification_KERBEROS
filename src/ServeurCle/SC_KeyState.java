package ServeurCle;

import GestionSocket.GestionSocket;
import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import Network.Constants.Server_Cle_constants;
import main.Serveur_Cle;
import Network.Request;
import Utils.ByteUtils;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
public class SC_KeyState extends SC_State {

    public SC_KeyState(GestionSocket gsocket, Serveur_Cle sc) {
        super(gsocket, sc);
    }
 
    @Override
    public void get_key(Request r) {
        try {
            String username=(String)r.getChargeUtile();
            
            //récupérer la clé dans un fichier .key
            Cle k=sc.getKey(username);
            
            //Chiffrer l'objet Clé
            Cipher c=Cipher.getInstance(sc.getAlgorithm()+'/'+sc.getCipherMode()+'/'
                    +sc.getPadding());
            c.init(Cipher.ENCRYPT_MODE, sc.getDh().getSecretKey());
            byte[] cipherKey=c.doFinal(ByteUtils.toByteArray((Object)k));
            
            //envoyer la clé chiffrée
            r=new Request(Server_Cle_constants.YES);
            r.setChargeUtile(ByteUtils.toObject(cipherKey));
            gsocket.Send(r);
            
            //pas d'erreur: mettre acutalState à l'état initial
            sc.setActualState(new SC_Init(gsocket, sc));
            
        } catch (NoSuchAlgorithmException | IOException | NoSuchPaddingException | NoSuchProviderException | 
                NoSuchCleException | InvalidKeyException | ClassNotFoundException | NoSuchChiffrementException ex) {
            Logger.getLogger(SC_KeyState.class.getName()).log(Level.SEVERE, null, ex);
            
            //Envoyer erreur au client
            r=new Request(Server_Cle_constants.FAIL);
            r.setChargeUtile(Server_Cle_constants.KEYFAIL);
            gsocket.Send(r);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(SC_KeyState.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
