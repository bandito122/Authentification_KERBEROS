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
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import main.Serveur_Cle;

/*
 * @author Julien
 */
public class SC_DH extends SC_State {

    public SC_DH(GestionSocket gsocket, Serveur_Cle sc) {
        super(gsocket, sc);
    }
    
    @Override
    public void DH_SetPublicKey(Request r) {
        try {
            //récupère la partie publique du client
            sc.setDHKey(ByteUtils.toByteArray((ArrayList<Byte>) r.getChargeUtile()));
            
            //envoit sa partie publique
            r=new Request(Server_Cle_constants.DHPK);
            r.setChargeUtile(ByteUtils.toObject(sc.getDh().getPublicKey().getEncoded()));
            gsocket.Send(r);
            
            //si ok, passer à l'état suivant
            sc.setActualState(new SC_KeyState(gsocket, sc));
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException | InvalidKeyException ex) {
            Logger.getLogger(SC_DH.class.getName()).log(Level.SEVERE, null, ex);
            
            //envoyer message erreur au client
            r=new Request(Server_Cle_constants.FAIL);
            r.setChargeUtile(Server_Cle_constants.DHFAILED);
            gsocket.Send(r);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(SC_DH.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
