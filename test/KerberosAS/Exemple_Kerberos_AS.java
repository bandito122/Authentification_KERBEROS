package KerberosAS;

import JavaLibrary.Crypto.ChiffreImpl.ChiffreDES;
import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.DiffieHellman.DiffieHellman;
import JavaLibrary.Crypto.HMAC.HMAC;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Kerberos.AuthenticatorCS;
import JavaLibrary.Utils.ByteUtils;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import Kerberos.KAS_CST;
import Kerberos.KS_CST;
import Kerberos.KTGS_CST;
import Kerberos.TicketTGS;
import Serializator.KeySerializator;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.time.LocalDate;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*
 * @author Julien
 */
public class Exemple_Kerberos_AS
{

    public static int PORT_AS = 6002, PORT_TGS = 6003;
    public static String KEY_TYPE = "DES",
            HOST = "localhost",
            USERNAME = "julien",
            PWD = "test",
            //PWD="", //debug pour créer une erreur
            TGS_NAME = "default",
            SERVER = "default";
        //TGS_NAME="echec"; //debug pour créer une erreur

    //à mettre dans configuration     
    public static String ENCODING = "UTF-8",
            LDF_PATTERN = "dd/MM/yyyy HH:00",
            ALGORITHM = "DES";

    public static String KEY_DIR = System.getProperty("user.home") + System.getProperty("file.separator")
            + "client_cle" + System.getProperty("file.separator") + "exemple_cle.key";

    static Chiffrement chKc, chKctgs;
    static Cle Kc, Kctgs;
    static GestionSocket gsocket_AS, gsocket_TGS;
    static Socket s;
    static Cipher cipher;
    static NetworkPacket paramAS;

    public static void main(String[] args)
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());
            //lire la clé utilisateur long terme, ici dans un fichier, en vrai reçue du serveur clé
            Kc = KeySerializator.loadKey(KEY_DIR, ALGORITHM);
            chKctgs = (Chiffrement) CryptoManager.newInstance(ALGORITHM);
            chKc = (Chiffrement) CryptoManager.newInstance(ALGORITHM);
            chKc.init(Kc);
            s = new Socket(HOST, PORT_AS);
            gsocket_AS = new GestionSocket(s);
            System.out.printf("[CLIENT]Connected to server %s:%d\n", HOST, PORT_AS);

            //test KerberosAS
            ASAuthentication();
            gsocket_AS.Close();

            System.out.println("[CLIENT]Attaquons le serveur KerberosTGS");

            //test KerberosTGS
            SendSecondPacket();
        }
        catch (IOException | ClassNotFoundException | NoSuchAlgorithmException |
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex)
        {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
            System.exit(-1);
        }
        catch (NoSuchProviderException | NoSuchChiffrementException ex)
        {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //s'authentifier auprès du Kerberos AS
    private static void ASAuthentication() throws NoSuchAlgorithmException, IOException,
            InvalidKeyException, IllegalBlockSizeException, ClassNotFoundException,
            BadPaddingException, NoSuchProviderException, NoSuchChiffrementException
    {
        //pour ne pas que le PWD passe en clair!
        SecurePasswordSha256 sp = new SecurePasswordSha256(PWD);

        //construit la liste des paramètres et envoyer
        NetworkPacket np = new NetworkPacket(KAS_CST.INIT);
        np.add(KAS_CST.USERNAME, USERNAME);
        np.add(KAS_CST.SALT, sp.getSalt());
        np.add(KAS_CST.PWD, sp.getHashedPassword());
        np.add(KAS_CST.INTERFACE, InetAddress.getLocalHost().getHostAddress());
        np.add(KAS_CST.TGSNAME, TGS_NAME);
        np.add(KAS_CST.DATETIME, LocalDate.now());
        System.out.printf("[CLIENT]Local Host: %s\n",InetAddress.getLocalHost().getHostAddress());
        gsocket_AS.Send(np);

        //Lire la réponse. De +, on est en partiellement chiffré donc pas de CipherGestionSocket
        paramAS = (NetworkPacket) gsocket_AS.Receive();
        //Avec une socket null, CGS permet de (dé)chiffrer simplement
        CipherGestionSocket cgs = new CipherGestionSocket(null, chKc);
        if (paramAS.getType() == KAS_CST.YES)
        {
            //OK
            System.out.printf("[CLIENT]User %s connecté!\n", USERNAME);
            chKc.init(Kc);

            //Envoie le paquet chiffré avec Kctgs
            System.out.println("CLE = " + paramAS.get(KAS_CST.KCTGS).toString());
            Kctgs = (Cle) ByteUtils.toObject(cgs.decrypte(paramAS.get(KAS_CST.KCTGS)));
            int version = (Integer) ByteUtils.toObject(cgs.decrypte(paramAS.get(KAS_CST.VERSION)));
            String tgServerAddr = (String) ByteUtils.toObject(cgs.decrypte(paramAS.get(KAS_CST.TGSNAME)));

            System.out.printf("[CLIENT]KerberosAS est de version %d, le nom du TGS est: %s\n",
                    version, tgServerAddr);

            //quitter la connexion au KerberosAS
            NetworkPacket response = new NetworkPacket(KAS_CST.QUIT);
            gsocket_AS.Send(response);
            gsocket_AS.Close();

            //test
            Chiffrement chKctgs_test = (Chiffrement) CryptoManager.newInstance(ALGORITHM);
            chKctgs_test.init(Kctgs);
            String ciphertext = chKctgs_test.crypte("Charbon");
            System.out.printf("texte chiffré: %s\n", Arrays.toString(ciphertext.getBytes()));
            String plainText = chKctgs_test.decrypte(ciphertext);
            System.out.printf("text déchiffré: %s\n", Arrays.toString(plainText.getBytes()));
            System.out.printf("text déchiffré: %s\n", plainText);
        }
        else
        { //pas ok: si clé pas trouvée ?
            System.out.printf("[CLIENT]Message received: %s\n",
                    ((String) paramAS.get(KAS_CST.MSG)));
            //stop();
            TransferLongTermKey();

        }

    }

    //si serveur ne connaît pas la clé long terme du client, il faut lui transférer
    private static void TransferLongTermKey()
    {
        try
        {
            System.out.println("Il faut générer un Diffie Hellman pour transmettre la clé long terme");
            //Réaliser un DH
            NetworkPacket request = new NetworkPacket(KAS_CST.TRANSFER_KEY);
            DiffieHellman dh = new DiffieHellman();
            request.add(KAS_CST.PK, dh.getPublicKey().getEncoded()); //envoit sa partie publique
            System.out.println("Diffie Hellman généré, on l'envoie au serveur");
            gsocket_AS.Send(request);

            NetworkPacket answer = (NetworkPacket) gsocket_AS.Receive();
            if (answer.getType() == KAS_CST.YES)
            { //reçoit la partie publique du serveur
                dh.setPublicKey((byte[]) answer.get(KAS_CST.PK));
            }
            else
            { //erreur
                System.out.printf("[CLIENT]Message received: %s\n",
                        ((String) answer.get(KAS_CST.MSG)));
                stop();
            }
            //envoyer que tout est OK de notre côté
            NetworkPacket response = new NetworkPacket(KAS_CST.YES);
            gsocket_AS.Send(response);

            //chiffrer la connexion
            ChiffreDES tmpCh = (ChiffreDES) CryptoManager.newInstance(ALGORITHM);
            tmpCh.init(new CleDES(dh.getSecretKey()));
            CipherGestionSocket cgs = new CipherGestionSocket(null, tmpCh);

            //envoyer la clé long terme
            NetworkPacket longTermKeyPacket = new NetworkPacket(KAS_CST.TRANSFER_KEY);
            longTermKeyPacket.add(KAS_CST.KC, cgs.crypte(Kc));
            longTermKeyPacket.add(KAS_CST.USERNAME, cgs.crypte(USERNAME));
            gsocket_AS.Send(longTermKeyPacket);

            NetworkPacket answer2 = (NetworkPacket) gsocket_AS.Receive();
            if (answer2.getType() == KAS_CST.FAIL)
            {//si erreur
                System.out.printf("[CLIENT]Message received: %s\n",
                        ((String) answer2.get(KAS_CST.MSG)));
            }
            else
            { //OK

                ASAuthentication();
            }
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidParameterSpecException |
                InvalidAlgorithmParameterException | IOException | InvalidKeyException |
                IllegalBlockSizeException | ClassNotFoundException | BadPaddingException |
                NoSuchChiffrementException | InvalidKeySpecException | InvalidParameterException ex)
        {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch (Exception ex)
        {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    //Communication avec le TGS
    private static void SendSecondPacket() throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, IOException,
            IllegalBlockSizeException, BadPaddingException, UnknownHostException,
            ClassNotFoundException, NoSuchChiffrementException
    {
        //Connexion au serveur TGS
        Socket s = new Socket(HOST, PORT_TGS);

        //Le paquet en entier n'est pas chiffré, juste le ticket!
        //TGS à besoin du ticket pour récupérer la clé de session
        //le ticket est chiffré avec la clé long terme de TGS
        gsocket_TGS = new GestionSocket(s);

        //crée le paquet et l'envoit!
        NetworkPacket tgsReq = new NetworkPacket(KTGS_CST.SEND_AUTHENTICATOR);
        tgsReq.add(KTGS_CST.TGS, (byte[]) paramAS.get(KAS_CST.TICKETGS)); //tgs déjà chiffré
        gsocket_TGS.Send(tgsReq);

        //lire réponse
        NetworkPacket ticketReponse = (NetworkPacket) gsocket_TGS.Receive();

        if (ticketReponse.getType() != KTGS_CST.YES)
        { //erreur
            System.out.printf("[CLIENT]Erreur lors du SEND TICKET: %s\n",
                    ticketReponse.get(KTGS_CST.MSG));
            gsocket_TGS.Close();
            System.exit(-1);
        }
        else
        { //ok
            System.out.printf("[CLIENT]Serveur TGS ok\n");
        }

        //la communication est maintenant chiffrée par kc,tgs: une clé temporaire
        //entre le client et le serveur TGS
        chKctgs.init(Kctgs);
        //gsocket_TGS=(GestionSocket) new CipherGestionSocket(gsocket_TGS.ois, gsocket_TGS.oos, chKctgs);

        //on doit ensuite envoyer l'ACS: on le prépare donc
        HMAC hmac = new HMAC();
        hmac.generate(((CleDES) Kctgs).getCle(), USERNAME + LocalDate.now().toString());
        AuthenticatorCS acs = new AuthenticatorCS(USERNAME,
                LocalDate.now(), hmac);

        //préparer le paquet avec l'ACS à envoyer
        NetworkPacket tgsParam = new NetworkPacket(KTGS_CST.SEND_TICKET);
        tgsParam.add(KTGS_CST.ACS, acs);
        tgsParam.add(KTGS_CST.USERNAME, USERNAME); //nom du client
        gsocket_TGS.Send(tgsParam);

        //lit la réponse    
        NetworkPacket paramTGS = (NetworkPacket) gsocket_TGS.Receive();
        if (paramTGS.getType() == KTGS_CST.YES)
        {
            Chiffrement chKCTGS = (Chiffrement) CryptoManager.newInstance(ALGORITHM);
            chKCTGS.init(Kctgs);
            CipherGestionSocket cgs = new CipherGestionSocket(null, chKCTGS);
            System.out.println("paramAS.get(KTGS_CST.KCS)= " + paramTGS.get(KTGS_CST.KCS));
            System.out.println("cgs.decrypte(paramAS.get(KTGS_CST.KCS))= " +cgs.decrypte(paramTGS.get(KTGS_CST.KCS)));
            System.out.println("ByteUtils.toObject(cgs.decrypte(paramAS.get(KTGS_CST.KCS)))" + ByteUtils.toObject(cgs.decrypte(paramTGS.get(KTGS_CST.KCS))));
            Cle kcs = (Cle) ByteUtils.toObject(cgs.decrypte(paramTGS.get(KTGS_CST.KCS)));
            int version = (Integer) ByteUtils.toObject(cgs.decrypte(paramTGS.get(KTGS_CST.VERSION)));
            System.out.println("version  =  " + version);
            String nomServeur = (String) ByteUtils.toObject(cgs.decrypte(paramTGS.get(KTGS_CST.SERVER_NAME)));
            System.out.println("nomServeur = " + nomServeur);
            String ldt = (String) ByteUtils.toObject(cgs.decrypte(paramTGS.get((KTGS_CST.DATETIME)))).toString();
            System.out.println("temps = " + ldt);
            
            
            //seconde partie par ks... on ne sait pas la déchiffrer!

            //TicketTGS ticketTgs = (TicketTGS) paramTGS.get(KTGS_CST.TICKET_SERVER);
            System.out.println("OKOKOKKOKOK");
        }
        else
        {
            System.out.printf("[CLIENT]Something went wrong: %s\n",
                    (String) paramTGS.get(KTGS_CST.MSG));
        }
    }

    private static void stop()
    {
        try
        {
            NetworkPacket r = new NetworkPacket(KAS_CST.QUIT);
            gsocket_AS.Send(r);
            s.close();
            System.exit(-1);
        }
        catch (IOException ex)
        {
            Logger.getLogger(Exemple_Kerberos_AS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
