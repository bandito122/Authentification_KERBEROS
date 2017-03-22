package ServeurCle.State;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Serializator.KeySerializator;
import ServeurCle.SC_CST;
import main.Serveur_Cle;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * @author Julien
 */
public class SC_GetKey_State extends SC_State {

    public SC_GetKey_State(GestionSocket gsocket, Serveur_Cle sc) {
        super(gsocket, sc);
    }
 
    @Override
    public void get_key(NetworkPacket r) {
        Chiffrement ch=context.getChiffrement();
        try {
            //récupérer la clé dans un fichier username.key, si elle n'existe pas, elle est crée
            Cle cle=KeySerializator.getKey(Serveur_Cle.DIRECTORY+
                    (String)r.get(SC_CST.USERNAME)+Serveur_Cle.EXT, context.getAlgorithm());
            
            //Chiffrer l'objet Clé et l'envoyer            
            r=new NetworkPacket(SC_CST.YES);
            r.add(SC_CST.SECRETKEY, cle);
            
            //si pas d'erreur: mettre acutalState à l'état initial
            context.setActualState(new SC_Init_State(gsocket, context));
            
        } catch (NoSuchAlgorithmException | IOException | NoSuchProviderException | 
                NoSuchCleException | ClassNotFoundException | NoSuchChiffrementException ex) {
            Logger.getLogger(SC_GetKey_State.class.getName()).log(Level.SEVERE, null, ex);
            //Envoyer erreur au client
            r=new NetworkPacket(SC_CST.FAIL);
            r.add(SC_CST.MSG,SC_CST.KEY_FAILED);   
        } finally {
            gsocket.Send(r);
        }
    }
}
