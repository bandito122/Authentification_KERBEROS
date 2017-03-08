package ServeurCle;

import Network.Request;
import GestionSocket.GestionSocket;
import Network.Constants.Server_Cle_constants;
import Utils.ByteUtils;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import main.Serveur_Cle;

/*
 * @author Julien
 */
public class SC_DHState extends SC_State {

    public SC_DHState(GestionSocket gsocket, Serveur_Cle sc) {
        super(gsocket, sc);
    }
    
    @Override
    public void DH_SetPublicKey(Request r) {
        try {
            sc.setDHKey(ByteUtils.toByteArray(r.getChargeUtile()));
            //si ok, passer à l'état suivant
            sc.setActualState(new SC_DHState(gsocket, sc));
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException | InvalidKeyException ex) {
            Logger.getLogger(SC_DHState.class.getName()).log(Level.SEVERE, null, ex);
            
            //envoyer message erreur au client
            r=new Request(Server_Cle_constants.FAIL);
            r.setChargeUtile(Server_Cle_constants.DHFAILED);
            gsocket.Send(r);
        }
    }
}
