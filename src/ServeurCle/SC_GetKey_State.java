package ServeurCle;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import main.Serveur_Cle;
import Utils.ByteUtils;
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
        try {
            //récupérer la clé dans un fichier .key
            Cle cle=sc.getKey((String)r.get(SC_CST.USERNAME));
            
            //Chiffrer l'objet Clé
            /*Cipher c=Cipher.getInstance(sc.getAlgorithm()+'/'+sc.getCipher()+'/'
                    +sc.getPadding());
            c.init(Cipher.ENCRYPT_MODE, sc.getDh().getSecretKey());*/
            Chiffrement ch=sc.getChiffrement();
            //byte[] cipherKey=c.doFinal(ByteUtils.toByteArray((Object)cle));
            byte[] cipherKey=ch.crypte(ByteUtils.toByteArray((Object) cle));
            System.out.printf("[SERVER]Clé chiffrée: longueur %d bytes\n",cipherKey.length);
            //envoyer la clé chiffrée
            r=new NetworkPacket(SC_CST.YES);
            r.add(SC_CST.SECRETKEY, cipherKey);
            gsocket.Send(r);
            
            //pas d'erreur: mettre acutalState à l'état initial
            sc.setActualState(new SC_Init_State(gsocket, sc));
            
        } catch (NoSuchAlgorithmException | IOException | 
                NoSuchProviderException | NoSuchCleException | 
                ClassNotFoundException | NoSuchChiffrementException ex) {
            Logger.getLogger(SC_GetKey_State.class.getName()).log(Level.SEVERE, null, ex);
            
            //Envoyer erreur au client
            r=new NetworkPacket(SC_CST.FAIL);
            r.add(SC_CST.MSG,SC_CST.KEYFAILED);   
            gsocket.Send(r);
        }
    }
}
