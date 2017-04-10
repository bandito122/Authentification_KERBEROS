package Kerberos.TGSState;

import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Kerberos.KTGS_CST;
import ServeurCle.SC_CST;
import java.io.IOException;
import main.KerberosTGS;

/*
 * @author Julien
 */
public abstract class TGS_State {
    protected GestionSocket gsocket;
    protected final KerberosTGS context;

    public TGS_State(GestionSocket gs,KerberosTGS context) {
        this.context = context;
        this.gsocket=gs;
    }
    
    public void HandleTicket(NetworkPacket r) throws IOException {
        OperationNotPermitted("Handle Ticket");
    }
    
    public void HandleAuthenticator(NetworkPacket req) {
        OperationNotPermitted("Handle ACS ");
    }
    
    public void HandleQuit(NetworkPacket np) {
        gsocket.Close();
        context.stop();
    }
    
    public void OperationNotPermitted(String operation) {
        NetworkPacket r=new NetworkPacket(SC_CST.FAIL);
        r.add(KTGS_CST.MSG, String.format(KTGS_CST.OPNOTPERMITTED, operation));
        gsocket.Send(r);
    }
}
