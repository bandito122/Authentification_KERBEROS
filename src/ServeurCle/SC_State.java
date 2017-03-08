package ServeurCle;

import GestionSocket.GestionSocket;
import Network.Constants.Server_Cle_constants;
import Network.Request;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import main.Serveur_Cle;

/*
 * @author Julien
 * Serveur_Clé_State: représente l'état dans lequel se trouve le Serveur Clé
 */
public abstract class SC_State {
    
    protected final GestionSocket gsocket;
    protected final Serveur_Cle sc;

    public SC_State(GestionSocket gsocket, Serveur_Cle sc) {
        this.gsocket = gsocket;
        this.sc=sc;
    }
    
    public void instantiate_DH(Request r) {
        this.OperationNotPermitted("instantiate_DH");
    }
    
    public void DH_SetPublicKey(Request r) {
        this.OperationNotPermitted("DH_SetPublicKey");
    }
    
    public void get_key(Request r) {
        this.OperationNotPermitted("get_key");
    }
    
    public void OperationNotPermitted(String operation) {
        Request r=new Request(Server_Cle_constants.FAIL);
        r.setChargeUtile(String.format(Server_Cle_constants.OPNOTPERMITTED, operation));
        gsocket.Send(r);
    }
}
