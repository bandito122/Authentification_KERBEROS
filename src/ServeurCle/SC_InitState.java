package ServeurCle;

import DiffieHellman.DHServer;
import GestionSocket.GestionSocket;
import Network.Constants.Server_Cle_constants;
import Network.Request;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;
import main.Serveur_Cle;

/*
 * @author Julien
 */
public class SC_InitState extends SC_State {

    public SC_InitState(GestionSocket gsocket, Serveur_Cle sc) {
        super(gsocket,sc);
    }
    
    @Override
    public void instantiate_DH(Request r) {
        try {
            sc.setDh(new DHServer());
            //si ok, passer à l'état suivant
            sc.setActualState(new SC_DHState(gsocket, sc));
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(SC_InitState.class.getName()).log(Level.SEVERE, null, ex);
            
            //envoyer erreur au client
            r=new Request(Server_Cle_constants.FAIL);
            r.setChargeUtile(Server_Cle_constants.DHFAILED);
            gsocket.Send(r);
        }
    }
    
}
