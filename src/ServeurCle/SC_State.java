package ServeurCle;

import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import main.Serveur_Cle;

/*
 * @author Julien
 * Serveur_Clé_State: représente l'état dans lequel se trouve le Serveur Clé
 */
public abstract class SC_State {
    
    protected GestionSocket gsocket;
    protected final Serveur_Cle sc;

    public SC_State(GestionSocket gsocket, Serveur_Cle sc) {
        this.gsocket = gsocket;
        this.sc=sc;
    }
    
    public void init_step(NetworkPacket r) {
        this.OperationNotPermitted("instantiate_DH");
    }
    
    public void DHPK_step(NetworkPacket r) {
        this.OperationNotPermitted("DH_SetPublicKey");
    }
    
    public void get_key(NetworkPacket r) {
        this.OperationNotPermitted("get_key");
    }
    
    public void OperationNotPermitted(String operation) {
        NetworkPacket r=new NetworkPacket(SC_CST.FAIL);
        r.add(SC_CST.MSG, String.format(SC_CST.OPNOTPERMITTED, operation));
        gsocket.Send(r);
    }
}
