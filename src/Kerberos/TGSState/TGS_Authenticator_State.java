package Kerberos.TGSState;

import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Kerberos.AuthenticatorCS;
import Kerberos.KTGS_CST;
import Kerberos.TicketTGS;
import java.security.InvalidParameterException;
import java.time.LocalDate;
import java.util.logging.Level;
import java.util.logging.Logger;
import main.KerberosTGS;

/*
 * @author Julien
 */
public class TGS_Authenticator_State extends TGS_State {

    public TGS_Authenticator_State(GestionSocket gs, KerberosTGS context) {
        super(gs,context);
    }
    
    @Override
    public void HandleAuthenticator(NetworkPacket req) {
        NetworkPacket reponse = null;
        try {
            //récupérer l'authenticatorCS pour l'analyser
            AuthenticatorCS acs=(AuthenticatorCS) req.get(KTGS_CST.ACS);
            
            //regarder si validité dépassée | si validité trop loin dans le passé
            LocalDate now=LocalDate.now();
            if(acs.tv.compareTo(now.plusDays(context.validite))>0 ||
                    acs.tv.compareTo(now.minusDays(context.validite))<0) {
                throw new InvalidParameterException(KTGS_CST.DATETIME_FAILED);
            }
            
            //Envoyer au client la réponse
            reponse = new NetworkPacket(KTGS_CST.YES);
            
            //Chiffrer avec la clé de session Kc,tgs
            //générer une clé de session client-serveur
            context.kcs=CryptoManager.genereCle(context.algorithm);
            ((CleDES)context.kcs).generateNew();
            
            reponse.add(KTGS_CST.KCS, context.kcs);
            //envoyer la version
            reponse.add(KTGS_CST.VERSION, context.version);
            
            //le nom du serveur à atteindre
            reponse.add(KTGS_CST.SERVER_NAME, context.name);
            
            reponse.add(KTGS_CST.DATETIME, LocalDate.now());
            
            TicketTGS ticketTGS=new TicketTGS(acs.client, "localhost:6004", 
                    LocalDate.now().plusDays(context.validite), context.kcs);

            reponse.add(KTGS_CST.TICKET_SERVER, ticketTGS);
        } catch (Exception ex) {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
            reponse=new NetworkPacket(KTGS_CST.FAIL);
            reponse.add(KTGS_CST.MSG, ex.getMessage());
            
        } finally {
            gsocket.Send(reponse);
        }
    }
    
}
