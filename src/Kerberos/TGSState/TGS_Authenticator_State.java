package Kerberos.TGSState;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Kerberos.AuthenticatorCS;
import Kerberos.KAS_CST;
import Kerberos.KTGS_CST;
import Kerberos.TicketTCS;
import Kerberos.TicketTGS;
import java.security.InvalidParameterException;
import java.time.LocalDate;
import java.util.logging.Level;
import java.util.logging.Logger;
import main.KerberosTGS;

/*
 * @author Julien
 */
public class TGS_Authenticator_State extends TGS_State
{

    public TGS_Authenticator_State(GestionSocket gs, KerberosTGS context)
    {
        super(gs, context);
    }

    @Override
    public void HandleAuthenticator(NetworkPacket req)
    {
        NetworkPacket reponse = null;
        try
        {
            //récupérer l'authenticatorCS pour l'analyser
            AuthenticatorCS acs = (AuthenticatorCS) req.get(KTGS_CST.ACS);

            //regarder si validité dépassée | si validité trop loin dans le passé
            LocalDate now = LocalDate.now();
            if (acs.tv.compareTo(now.plusDays(context.validite)) > 0|| acs.tv.compareTo(now.minusDays(context.validite)) < 0)
            {
                throw new InvalidParameterException(KTGS_CST.DATETIME_FAILED);
            }

            //Envoyer au client la réponse
            System.out.println("Envoie de la réponse concernant l'acs au client...");
            reponse = new NetworkPacket(KTGS_CST.YES);

            //Chiffrer avec la clé de session Kc,tgs
            //générer une clé de session client-serveur
            context.kcs = CryptoManager.genereCle(context.algorithm);
            ((CleDES) context.kcs).generateNew();
            
            Chiffrement chKCTGS = (Chiffrement) CryptoManager.newInstance(context.algorithm);
            chKCTGS.init(context.kctgs);
            CipherGestionSocket cgs = new CipherGestionSocket(null, chKCTGS);
            
             /*envoie au client de : la clé de session KCS, version,nom du serveur crypté avec kc,tgs */
            
            //crypter clé de session KCS 
            
            reponse.add(KTGS_CST.KCS, cgs.crypte(context.kcs));
            //crypter la version 
            reponse.add(KTGS_CST.VERSION, cgs.crypte((Integer)context.version));

            //crypter le ns 
            reponse.add(KTGS_CST.SERVER_NAME, cgs.crypte("localhost:6004")); // le nom du serveur est le (seul) serveur qu'il peut atteindre... (serveur analyse)
            
            //crypter la date
            reponse.add(KTGS_CST.DATETIME, cgs.crypte(LocalDate.now()));
  
            //envoyer localhost:6004 ne sert à rien, le client ne sait pas lire le ticket TGS, ce n'est utile qu'au serveur...
            TicketTCS ticketTCS = new TicketTCS(acs.client, "localhost:6004", LocalDate.now().plusDays(context.validite), context.kcs);
            
            // on envoie le ticket TGS crypté avec la clé du serveur analyse KS
            
            Chiffrement chKS = (Chiffrement) CryptoManager.newInstance(context.algorithm);
            chKS.init(context.ks);
            cgs = new CipherGestionSocket(null, chKS);
            reponse.add(KTGS_CST.TICKET_SERVER, cgs.crypte(ticketTCS));

            
        }
        catch (Exception ex)
        {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
            reponse = new NetworkPacket(KTGS_CST.FAIL);
            reponse.add(KTGS_CST.MSG, ex.getMessage());

        }
        finally
        {
            gsocket.Send(reponse);
        }
    }

}
