package ServeurCle;

import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
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
public class SC_DHPK_State extends SC_State {

    public SC_DHPK_State(GestionSocket gsocket, Serveur_Cle sc) {
        super(gsocket, sc);
    }
    
    @Override
    public void DHPK_step(NetworkPacket r) {
        try {
            //récupère la partie publique du client
            sc.setDHKey((byte[]) r.get(SC_CST.PK));
            
            //envoit sa partie publique
            r=new NetworkPacket(SC_CST.YES);
            r.add(SC_CST.PK, sc.getDh().getPublicKey().getEncoded());
            gsocket.Send(r);
            
            //initialiser la clé du serveur
            sc.createChiffrement(sc.getDh().getSecretKey());
            //si ok, passer à l'état suivant
            sc.setActualState(new SC_GetKey_State(gsocket, sc));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | 
                InvalidAlgorithmParameterException | InvalidKeyException |
                NoSuchChiffrementException ex) {
            Logger.getLogger(SC_DHPK_State.class.getName()).log(Level.SEVERE, null, ex);
            
            //envoyer message erreur au client
            r=new NetworkPacket(SC_CST.FAIL);
            r.add(SC_CST.MSG,SC_CST.DHFAILED);   
            gsocket.Send(r);
        }
    }
}
