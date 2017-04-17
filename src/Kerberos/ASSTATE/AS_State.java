package Kerberos.ASSTATE;

import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Kerberos.KTGS_CST;
import ServeurCle.SC_CST;
import main.KerberosAS;

/*
 * @author Julien
 */
public abstract class AS_State {
    protected GestionSocket gsocket;
    protected KerberosAS context;
    
    public AS_State(GestionSocket gsocket, KerberosAS context){
        this.gsocket=gsocket;
        this.context=context;
    }
    
    public void HandleAuthentication(NetworkPacket np) {
        OperationNotPermitted("Handle Authentication");
    }
    
    public void HandleTransferKey(NetworkPacket np) {
        OperationNotPermitted("Handle No Key Found");
    }
    
    public void HandleQuit(NetworkPacket np) {
        gsocket.Close();
    }

    public void OperationNotPermitted(String operation) {
        NetworkPacket r=new NetworkPacket(SC_CST.FAIL);
        r.add(KTGS_CST.MSG, String.format(KTGS_CST.OPNOTPERMITTED, operation));
        gsocket.Send(r);
    }
}
