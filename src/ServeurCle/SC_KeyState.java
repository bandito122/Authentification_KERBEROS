package ServeurCle;

import GestionSocket.GestionSocket;
import Network.Constants.Server_Cle_constants;
import main.Serveur_Cle;
import Network.Request;
import Utils.ByteUtils;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

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
            ArrayList<String> param=(ArrayList<String>) r.getChargeUtile();
            //récupérer la clé dans le Keystore
            KeyStore ks=sc.getKeyStore();
            SecretKey sk=(SecretKey) ks.getKey(param.get(0),param.get(1).toCharArray());
            
            //Chiffrer
            Cipher c=Cipher.getInstance(sc.getAlgorithm()+'/'+sc.getCipherMode()+'/'
                    +sc.getPadding());
            c.init(Cipher.ENCRYPT_MODE, sc.getDh().getSecretKey());
            byte[] cipherKey=c.doFinal(sk.getEncoded());
            
            //envoyer
            r=new Request(Server_Cle_constants.YES);
            r.setChargeUtile(ByteUtils.toByteArray(cipherKey));
            gsocket.Send(r);
            
            //pas d'erreur: mettre acutalState à l'état initial
            sc.setActualState(new SC_InitState(gsocket, sc));
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | 
                NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException | IOException ex) {
            Logger.getLogger(SC_KeyState.class.getName()).log(Level.SEVERE, null, ex);
            
            //Envoyer erreur au client
            r=new Request(Server_Cle_constants.FAIL);
            r.setChargeUtile(Server_Cle_constants.KEYFAIL);
            gsocket.Send(r);
        }
    }
}
