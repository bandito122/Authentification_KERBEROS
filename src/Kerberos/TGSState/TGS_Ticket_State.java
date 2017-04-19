package Kerberos.TGSState;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import JavaLibrary.Utils.ByteUtils;
import Kerberos.KTGS_CST;
import Kerberos.TicketTGS;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.time.LocalDate;
import java.util.logging.Level;
import java.util.logging.Logger;
import main.KerberosTGS;

/*
 * @author Julien
 */
public class TGS_Ticket_State extends TGS_State
{

    public TGS_Ticket_State(GestionSocket gs, KerberosTGS context)
    {
        super(gs, context);
    }

    @Override
    public void HandleTicket(NetworkPacket np) throws IOException
    {
        NetworkPacket reponse = new NetworkPacket(0);
        boolean error = false;
        try
        {
            //Déchiffrer le ticket chiffré avec KTGS pour extraire kctgs, la clé de session
            CipherGestionSocket cgs = new CipherGestionSocket(null, context.ch_ktgs);
            TicketTGS ticketTGS = (TicketTGS) ByteUtils.toObject(cgs.decrypte(np.get(KTGS_CST.TGS)));

            //Vérifier la validité du ticket
            LocalDate now = LocalDate.now();

            //regarder si validité dépassée | si validité trop loin dans le passé
            if (ticketTGS.tv.compareTo(now.plusDays(context.validite)) > 0 || ticketTGS.tv.compareTo(now.minusDays(context.validite)) < 0)
            {
                throw new InvalidParameterException(KTGS_CST.DATETIME_FAILED);
            }

            //si tout est ok
            context.kctgs = ticketTGS.cleSession;
            context.ch_kctgs = (Chiffrement) CryptoManager.newInstance(context.algorithm);
            context.ch_kctgs.init(context.kctgs);

            //envoyer un YES
            reponse.setType(KTGS_CST.YES);
            reponse.add(KTGS_CST.MSG, KTGS_CST.SUCCESS);

            //Actualiser l'état du serveur TGS
            context.actualState = new TGS_Authenticator_State(gsocket, context);
        }
        catch (Exception ex)
        {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
            reponse.setType(KTGS_CST.FAIL);

            if (ex instanceof InvalidParameterException)
            {
                reponse.add(KTGS_CST.MSG, KTGS_CST.DATETIME_FAILED);
            }
            else
            {
                reponse.add(KTGS_CST.MSG, KTGS_CST.CMD_FAILED);
            }
            error = true;
        }
        finally
        {
            gsocket.Send(reponse);
            if (error)
            {
                //la clé de session sert à déchiffer l'authentificateur, on doit donc 
                //générer un nouveau CipherGestionSocket sur le chiffrement kctgs
                gsocket = new CipherGestionSocket(gsocket.getCSocket(), context.ch_kctgs);
            }
        }
    }

}
