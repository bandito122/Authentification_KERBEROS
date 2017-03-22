package main;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import Kerberos.AuthenticatorCS;
import Kerberos.TicketTGS;
import JavaLibrary.Utils.ByteUtils;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import Kerberos.KAS_CST;
import Kerberos.KTGS_CST;
import Serializator.KeySerializator;

/*
 * @author Julien
 * ATTENTION: CE SERVEUR PRODUIT LA CLE LONG TERME DU SERVEUR A ATTEINDRE :
 * C/C LE FICHIER DEFAULT_SERVERKEY.KEY VERS LE DOSSIER DU SERVEUR...
 */
public class KerberosTGS {
    private static final String DIRECTORY=System.getProperty("user.home")+ System.getProperty("file.separator")+
        "kerberos_tgs"+ System.getProperty("file.separator"),  
        CONFIG_FILE=DIRECTORY+"config.properties", USERS_FILE=DIRECTORY+"users.properties", EXT=".serverkey",
            SERVER_EXT=".key",
            KEY_FILE=DIRECTORY+"ktgs"+EXT,
            SERVERKEY_FILE=DIRECTORY+"default_serverkey"+SERVER_EXT;
    
    private static final int VERSION=2;
    private static final String LDF_PATTERN="dd/MM/yyyy HH:00", ENCODING="UTF-8";
    private static final long VALIDITY_DAY=1;
    
    private Properties config, users;
    private boolean quit;
    private int port;
    private String provider, algorithm, cipherMode, padding, 
            transformation;
    
    private SecurePasswordSha256 sp;
    private GestionSocket gsocket;
    private String name;
    private Cle ktgs,kctgs, kcs, ks;
    private Chiffrement ch_ktgs, ch_ks, ch_kctgs;
    
    public KerberosTGS(String name) {
        try {
            this.name=name;
            loadConfig();
            loadKeys();
        } catch (IOException | NoSuchFieldException | ClassNotFoundException | 
                NoSuchChiffrementException |NoSuchCleException | 
                NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(KerberosAS.class.getName()).log(Level.SEVERE, null, ex);
            System.exit(-1);
        }
        
        try {
            startListening();
        } catch (IOException | NoSuchPaddingException ex) {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void loadConfig() throws IOException, NoSuchFieldException {
        //Check if properties exists
        config=new Properties();
        users=new Properties();
        
        config.load(new FileInputStream(CONFIG_FILE));
        users.load(new FileInputStream(USERS_FILE));
        
        String s_port=config.getProperty("port");
        algorithm=config.getProperty("algorithm");
        cipherMode=config.getProperty("cipher");
        padding=config.getProperty("padding");
        provider=config.getProperty("provider");
        if(algorithm==null || cipherMode==null || provider==null || padding==null || s_port==null) {
            throw new NoSuchFieldException();
        }
        
        port=Integer.valueOf(s_port);
        transformation=algorithm+'/'+cipherMode+'/'+padding;
    }
    
    public static void usage_file() {
        System.out.printf("Les fichiers de configuration %s et %s doivent se trouver dans le "
                + "dossier %s\n", CONFIG_FILE, USERS_FILE, DIRECTORY);
    }
    
    public static void usage_config() {
        System.out.printf("Le fichier %s doit comporter les Clés-Valeurs: port, keystore, "
                + "kspwd, algorithm, cipher, padding\n", CONFIG_FILE);
    }
    
    public static void main(String[] args) {
        new KerberosTGS("default");
    }

    private void startListening() throws IOException, NoSuchPaddingException {
        ServerSocket ss=new ServerSocket(port);
        System.out.printf("[KERBEROS TGS]Launched! waiting for client\n");
        Socket clientSocket=ss.accept();
        System.out.printf("[KERBEROS TGS] client connected: %s:%d\n", 
            clientSocket.getInetAddress().toString(), clientSocket.getPort());
            
        gsocket=new GestionSocket(clientSocket);
        
        while(!quit) {
            NetworkPacket req=(NetworkPacket) gsocket.Receive();
            if(req==null) {
                break;
            }
            switch(req.getType()) {
                case KTGS_CST.SENDTICKET: System.out.println("[KERBEROS TGS] SENDTICKETS request received");
                    HandleSendTicket(req);
                    break;
                case KTGS_CST.SENDACS: System.out.println("[KERBEROS TGS] SENDACS request received");
                    HandleSendACS(req);
                    break;
                default:
                    NetworkPacket r=new NetworkPacket(KAS_CST.FAIL);
                    //r.setChargeUtile(KTGS_CST.OPNOTPERMITTED);
                    gsocket.Send(r);
            }
        }
    }

    private void HandleSendTicket(NetworkPacket r) throws IOException {
        NetworkPacket reponse=new NetworkPacket(0);
        boolean error=false;
        try {
            //Déchiffrer le ticket chiffré avec KTGS pour extraire kctgs, la clé de session
            //TicketTGS ticketTGS=(TicketTGS) ByteUtils.toObject(ch_ktgs.decrypte((byte[])r.get(KTGS_CST.TICKETGS)));
            CipherGestionSocket cgs=new CipherGestionSocket(null, ch_ktgs);
            TicketTGS ticketTGS=(TicketTGS) ByteUtils.toObject(cgs.decrypte(r.get(KTGS_CST.TGS)));
            kctgs=ticketTGS.cleSession;
            ch_kctgs=(Chiffrement) CryptoManager.newInstance(algorithm);
            ch_kctgs.init(kctgs);
            
            //envoyer un YES
            reponse.setType(KTGS_CST.YES);
            reponse.add(KTGS_CST.MSG, KTGS_CST.SUCCESS);
        }catch(Exception ex) { // catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
            reponse.setType(KTGS_CST.FAIL);
            reponse.add(KTGS_CST.MSG, KTGS_CST.CMDFAILED);
            error=true;
        } finally {
            gsocket.Send(reponse);
            if(!error) {
                //la clé de session sert à déchiffer l'authentificateur, on doit donc 
                //générer un nouveau CipherGestionSocket sur le chiffrement kctgs
                gsocket=new CipherGestionSocket(gsocket.getCSocket(), ch_kctgs);
            }
        }
    }

    private void loadKeys() throws IOException, ClassNotFoundException, 
            NoSuchChiffrementException, NoSuchCleException, NoSuchAlgorithmException, 
            NoSuchProviderException {
        
        /*ObjectInputStream ois=new ObjectInputStream(new FileInputStream(KEY_FILE));
        ktgs=(Cle) ois.readObject();
        ois.close();*/
        //récupère la clé du serveur TGS
        ktgs=KeySerializator.loadKey(KEY_FILE, algorithm);
        
        /*ois=new ObjectInputStream(new FileInputStream(SERVERKEY_FILE));
        ks=(Cle) ois.readObject();
        ois.close();*/
        //récupère et crée si nécessaire la clé du serveur (pour la copier coller après :p)
        ks=KeySerializator.getKey(SERVERKEY_FILE, algorithm);
        
        //initialise les objets chiffrements
        ch_ktgs=(Chiffrement) CryptoManager.newInstance(algorithm);
        ch_ktgs.init(ktgs);
        ch_ks=(Chiffrement) CryptoManager.newInstance(algorithm);
        ch_ks.init(ks);
    }
    
    /**
     * A bouger dans la classe KTGS_CST
     * @return 
     */
    protected static String getDateTimeNow() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern(LDF_PATTERN));
    }

    private void HandleSendACS(NetworkPacket req) {   
        try {
            //récupérer l'authenticatorCS pour l'analyser
            AuthenticatorCS acs=(AuthenticatorCS) req.get(KTGS_CST.ACS);
            
            //!!!il faudrait vérifier les informations reçues!!!!
            
            //Envoyer au client la réponse
            NetworkPacket reponse=new NetworkPacket(KTGS_CST.YES);
            
            //Chiffrer avec la clé de session Kc,tgs
            //générer une clé de session client-serveur
            kcs=CryptoManager.genereCle(algorithm);
            ((CleDES)kcs).generateNew();
            
            reponse.add(KTGS_CST.KCS, kcs);
            //envoyer la version
            reponse.add(KTGS_CST.VERSION, VERSION);
            
            //le nom du serveur à atteindre
            reponse.add(KTGS_CST.SERVER_NAME, this.name);
            
            reponse.add(KTGS_CST.DATETIME, getDateTimeNow());
            
            TicketTGS ticketTGS=new TicketTGS(
                    acs.client, "localhost:6004", LocalDateTime.now(), kcs);

            reponse.add(KTGS_CST.TICKETGS, ticketTGS);
            gsocket.Send(reponse);
        } catch (NoSuchCleException ex) {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
