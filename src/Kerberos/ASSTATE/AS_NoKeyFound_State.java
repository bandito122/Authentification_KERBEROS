package Kerberos.ASSTATE;

import JavaLibrary.Crypto.ChiffreImpl.ChiffreDES;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.DiffieHellman.DiffieHellman;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import JavaLibrary.Utils.ByteUtils;
import Kerberos.KAS_CST;
import Serializator.KeySerializator;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import main.KerberosAS;

/*
 * @author Julien
 */
public class AS_NoKeyFound_State extends AS_State {

    public AS_NoKeyFound_State(GestionSocket gsocket, KerberosAS context) {
        super(gsocket, context);
    }
    
    @Override
    public void HandleTransferKey(NetworkPacket np) {
        NetworkPacket reponse=new NetworkPacket(KAS_CST.YES);
        try {
            System.out.println("[KERBEROS AS] DH en cours");
            //faire DH
            DiffieHellman dh=new DiffieHellman();
            dh.setDHParam((byte[]) np.get(KAS_CST.PK));
            
            NetworkPacket response=new NetworkPacket(KAS_CST.YES);
            response.add(KAS_CST.PK, dh.getPublicKey().getEncoded());
            gsocket.Send(response);
            System.out.println("[KERBEROS AS] DH fini");
            
            //attendre la réponse
            NetworkPacket keyPacket=(NetworkPacket) gsocket.Receive();
            if(keyPacket.getType()==KAS_CST.FAIL) { //en cas d'erreur côté client
                System.err.printf("[KERBEROS AS][Handle Transfer Key] Erreur: %s", keyPacket.get(KAS_CST.MSG));
                HandleQuit(np); //on stoppe la communication
            } else {//si tout va bien
                //créer une communication chiffrée
                ChiffreDES ch=(ChiffreDES) CryptoManager.newInstance(context.getAlgorithm());
                ch.init(new CleDES(dh.getSecretKey()));
                CipherGestionSocket cgs=new CipherGestionSocket(null, ch);
                
                System.out.println("Clé reçue: on la déchiffre...");
                //lire la clé long terme
                NetworkPacket longTermKeyPacket=(NetworkPacket) gsocket.Receive();
                Cle Kc=(Cle) ByteUtils.toObject(cgs.decrypte(longTermKeyPacket.get(KAS_CST.KC))); //récupérer la clé hors du packet
                String username=(String)ByteUtils.toObject(cgs.decrypte(longTermKeyPacket.get(KAS_CST.USERNAME)));
                System.out.println("Clé reçue: déchiffrement réussi");
                //la sérialiser sur disque
                KeySerializator.saveKey(context.getDIRECTORY()+username+context.getEXT()
                        , Kc);
                
                //OK -> nouvelle socket non chiffrée
                context.setState(new AS_Authentication_State(gsocket, context));
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidParameterSpecException | 
                InvalidAlgorithmParameterException | InvalidKeySpecException | InvalidKeyException | 
                NoSuchChiffrementException | IOException | ClassNotFoundException ex) {
            Logger.getLogger(AS_NoKeyFound_State.class.getName()).log(Level.SEVERE, null, ex);
            reponse.setType(KAS_CST.FAIL);
            reponse.add(KAS_CST.MSG, ex.getMessage());
        } finally {
            gsocket.Send(reponse);
        }
    }
}
