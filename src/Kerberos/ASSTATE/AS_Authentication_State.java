package Kerberos.ASSTATE;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Kerberos.KAS_CST;
import Kerberos.TicketTGS;
import Serializator.KeySerializator;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDate;
import java.util.logging.Level;
import java.util.logging.Logger;
import main.KerberosAS;

/*
 * @author Julien
 */
public class AS_Authentication_State extends AS_State
{

    public AS_Authentication_State(GestionSocket gsocket, KerberosAS context)
    {
        super(gsocket, context);
    }

    @Override
    public void HandleAuthentication(NetworkPacket np)
    {
        String directory = context.getDIRECTORY(), algorithm = context.getAlgorithm();

        //récupérer les paramètres
        Cle Kc, Kctgs, Ktgs;
        NetworkPacket reponse = new NetworkPacket(0);
        try
        {
            //authentifier le client + regarder si le serveur demandé existe
            String tgServerAddr = context.getTgServer().getProperty((String) np.get(KAS_CST.TGSNAME));
            boolean isConnected = context.connectUser((String) np.get(KAS_CST.USERNAME),(String) np.get(KAS_CST.SALT), (String) np.get(KAS_CST.PWD));
            boolean tgsFound = tgServerAddr != null;

            System.out.printf("[KerberosAS]Tentative de connexion:\n\t Username: %s, Hash PWD %s\n"+ "\t IP: %s Serveur à atteindre: %s Valeur temporelle: %s\n",
                    np.get(KAS_CST.USERNAME).toString(), (String) np.get(KAS_CST.PWD).toString(),
                    np.get(KAS_CST.INTERFACE).toString(), np.get(KAS_CST.TGSNAME).toString(),
                    np.get(KAS_CST.DATETIME).toString());

            if (isConnected && tgsFound)
            {
                //les hashed parameters sont identiques
                reponse.setType(KAS_CST.YES);

                //récupère la clé long terme du client correspondant
                Kc = KeySerializator.loadKey(
                        directory + (String) np.get(KAS_CST.USERNAME)
                        + context.getEXT(), algorithm);

                //génère une clé temporaire qui va permettre au client 
                //et au TGS de communiquer de manière sécurisée
                Kctgs = (CleDES) CryptoManager.genereCle(algorithm);
                if (Kctgs instanceof CleDES) //obliger ici
                {
                    ((CleDES) Kctgs).generateNew();
                }

                Chiffrement chKc = (Chiffrement) CryptoManager.newInstance(algorithm);
                chKc.init(Kc);
                CipherGestionSocket cgs = new CipherGestionSocket(null, chKc);
                //construit la première partie du paquet, à savoir:
                //{La clé de session,version,nom du serveur TGS} 
                //chiffré avec la clé long terme du client Kc
                reponse.add(KAS_CST.KCTGS, cgs.crypte(Kctgs));
                reponse.add(KAS_CST.VERSION, cgs.crypte((Integer) context.getVersion()));
                reponse.add(KAS_CST.TGSNAME, cgs.crypte(tgServerAddr));
                reponse.add(KAS_CST.DATETIME, LocalDate.now());

                //récupère la clé du serveur avec ce client et crypte le ticket avec
                Ktgs = KeySerializator.getKey(directory + (String) np.get(KAS_CST.USERNAME)+ context.getSERVER_EXT(), algorithm);

                //deuxieme partie de la réponse: le ticket TGS
                //{nom du client, son ip, validité du ticket, cle de session}
                // chiffré avec la clé du serveur
                TicketTGS ticketTGS = new TicketTGS((String) np.get(KAS_CST.USERNAME),(String) np.get(KAS_CST.INTERFACE),LocalDate.now().plusDays(context.getValidite()), Kctgs); //définir la validité... 24h?

                //pour chiffrer le tciket TGS avec la clé du serveur TGS
                Chiffrement chKtgs = (Chiffrement) CryptoManager.newInstance(algorithm);
                chKtgs.init(Ktgs);
                cgs = new CipherGestionSocket(null, chKtgs);
                reponse.add(KAS_CST.TICKETGS, cgs.crypte(ticketTGS));
                System.out.println("[KERBEROS AS]successful!");
            }
            else
            { // si user pas connected où si serveur tgs demandé pas trouvé: accès refusé
                reponse.setType(KAS_CST.NO);
                if (!isConnected)
                {
                    reponse.add(KAS_CST.MSG, KAS_CST.USER_NOT_FOUND);
                    System.err.printf("[KERBEROS AS]Username or password incorrect! : %s : %s\n",(String) np.get(KAS_CST.USERNAME), KAS_CST.USER_NOT_FOUND);

                }
                else if (!tgsFound)
                { //serveur tgs demandé pas trouvé
                    reponse.add(KAS_CST.MSG, KAS_CST.TGS_NOT_FOUND);
                    System.err.printf("[KERBEROS AS]Targeted TGS pas trouvé: %s : %s\n",
                            (String) np.get(KAS_CST.TGSNAME),
                            KAS_CST.TGS_NOT_FOUND);
                }
            }

            //donner l'état suivant: il n'y en a pas.
        }
        catch (FileNotFoundException e)
        {//clé d'utilisateur pas trouvé
            //Logger.getLogger(KerberosAS.class.getName()).log(Level.SEVERE, null, e);
            System.err.printf("Le fichier de la clé utilisateur n'a pas été trouvé. On se met en attente d'une clé quelconque transmise par DH.\n");
            reponse.setType(KAS_CST.FAIL_NO_KEY_FOUND);
            reponse.add(KAS_CST.MSG, KAS_CST.FAILURE + e.getMessage());
            //alors on la demande au client
            context.setState(new AS_NoKeyFound_State(gsocket, context));
        }
        catch (IOException | ClassNotFoundException | NoSuchProviderException |
                NoSuchChiffrementException | NoSuchCleException |
                NoSuchAlgorithmException | NullPointerException e)
        {
            Logger.getLogger(KerberosAS.class.getName()).log(Level.SEVERE, null, e);
            reponse.setType(KAS_CST.FAIL);
            reponse.add(KAS_CST.MSG, KAS_CST.FAILURE + e.getMessage());
        }
        finally
        {
            gsocket.Send(reponse);
        }
    }
}
