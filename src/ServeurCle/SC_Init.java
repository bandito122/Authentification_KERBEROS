package ServeurCle;

import GestionSocket.GestionSocket;
import JavaLibrary.Crypto.DiffieHellman.DHServer;
import Network.Constants.Server_Cle_constants;
import Network.Request;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import main.Serveur_Cle;

/*
 * @author Julien
 */
public class SC_Init extends SC_State {

    public SC_Init(GestionSocket gsocket, Serveur_Cle sc) {
        super(gsocket,sc);
    }
    
    @Override
    public void instantiate_DH(Request r) {
        boolean isConnected=false;
        try {
            ArrayList<String> parameters=(ArrayList<String>) r.getChargeUtile();
            System.out.printf("User %s with password %s is asking for DH\n",parameters.get(0),
                    parameters.get(1));
            //vérifier le mdp et user
            if(sc.connectUser(parameters.get(0), parameters.get(2), parameters.get(1))) {
                isConnected=true;
                //si les hashed parameters sont ok
                r=new Request(Server_Cle_constants.YES);
                System.out.println("connected!");
                
                //instancier DH server
                sc.setDh(new DHServer());
                
                //si ok, passer à l'état suivant
                sc.setActualState(new SC_DH(gsocket, sc));
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException ex) {            
            //La connexion échoue ne rien faire
        } finally {
            if(!isConnected) { //si la connexion à échouer
                r=new Request(Server_Cle_constants.FAIL);
                r.setChargeUtile(Server_Cle_constants.DHFAILED);   
            }
            gsocket.Send(r);
        }
    }
}
