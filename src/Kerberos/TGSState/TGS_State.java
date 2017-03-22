package Kerberos.TGSState;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import JavaLibrary.Utils.ByteUtils;
import Kerberos.AuthenticatorCS;
import Kerberos.KTGS_CST;
import Kerberos.TicketTGS;
import ServeurCle.SC_CST;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDate;
import java.util.logging.Level;
import java.util.logging.Logger;
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
    
    public void HandleSendTicket(NetworkPacket r) throws IOException {
        OperationNotPermitted("Handle Ticket State");
    }
    
    public void HandleSendACS(NetworkPacket req) {
        OperationNotPermitted("Handle ACS State");
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
