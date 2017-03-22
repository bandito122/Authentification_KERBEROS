package ServeurCle.State;

import JavaLibrary.Crypto.DiffieHellman.DiffieHellman;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import ServeurCle.SC_CST;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidParameterSpecException;
import main.Serveur_Cle;

/*
 * @author Julien
 */
public class SC_Init_State extends SC_State {

    public SC_Init_State(GestionSocket gsocket, Serveur_Cle sc) {
        super(gsocket,sc);
    }
    
    
    @Override
    public void init_step(NetworkPacket r) {
        boolean isConnected=false;
        try {
            System.out.printf("User %s with password %s is asking for DH\n",
                    r.get("username"), r.get("password"));
            
            //vérifier le mdp et user
            if(context.connectUser((String)r.get(SC_CST.USERNAME), 
                    (String)r.get(SC_CST.SALT), (String)r.get(SC_CST.PWD))) {
                isConnected=true;
                
                //si les hashed r sont ok
                r=new NetworkPacket(SC_CST.YES);
                System.out.println("connected!");
                
                //instancier DiffieHellman server
                context.setDh(new DiffieHellman());
                    
                //si ok, passer à l'état suivant
                context.setActualState(new SC_DHPK_State(gsocket, context));
            } else { //connexion échoue
                System.out.println("[SERVER]connection failed");
                r=new NetworkPacket(SC_CST.NO);
                r.add(SC_CST.MSG,SC_CST.LOGIN_FAILED);   
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException |
                InvalidParameterSpecException | InvalidAlgorithmParameterException e) {            
            r=new NetworkPacket(SC_CST.FAIL);
            r.add(SC_CST.MSG, SC_CST.KEY_FAILED+e.getMessage());
            
        } finally {
            gsocket.Send(r);
        }
    }
}
