package main;

import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;
import Kerberos.KAS_CST;
import Kerberos.KTGS_CST;
import Kerberos.TGSState.TGS_State;
import Kerberos.TGSState.TGS_Ticket_State;
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
    
    private Properties config, users;
    private boolean quit;
    public int port, version;
    public long validite;
    public String algorithm, name;
    
    private SecurePasswordSha256 sp;
    private GestionSocket gsocket;
    public Cle ktgs,kctgs, kcs, ks;
    public Chiffrement ch_ktgs, ch_ks, ch_kctgs;
    public TGS_State actualState;
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
        String s_version=config.getProperty("version");
        String s_validite=config.getProperty("validite");
        algorithm=config.getProperty("algorithm");
        if(algorithm==null || s_port==null || s_validite==null || s_version==null) {
            throw new NoSuchFieldException();
        }
        
        port=Integer.valueOf(s_port);
        version=Integer.valueOf(s_version);
        validite=Long.valueOf(s_validite);
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
        KerberosTGS kerberosTGS = new KerberosTGS("default");
    }

    private void startListening() throws IOException, NoSuchPaddingException {
        ServerSocket ss=new ServerSocket(port);
        System.out.printf("[KERBEROS TGS]Launched! waiting for client\n");
        Socket clientSocket=ss.accept();
        System.out.printf("[KERBEROS TGS] client connected: %s:%d\n", 
            clientSocket.getInetAddress().toString(), clientSocket.getPort());
            
        gsocket=new GestionSocket(clientSocket);
        this.actualState=new TGS_Ticket_State(gsocket, this);
        
        while(!quit) {
            NetworkPacket req=(NetworkPacket) gsocket.Receive();
            if(req==null) {
                break;
            }
            switch(req.getType()) {
                case KTGS_CST.SEND_AUTHENTICATOR: System.out.println("[KERBEROS TGS] SENDTICKETS request received");
                    this.actualState.HandleTicket(req);
                    break;
                case KTGS_CST.SEND_TICKET: System.out.println("[KERBEROS TGS] SENDACS request received");
                    this.actualState.HandleAuthenticator(req);
                    break;
                default:
                    NetworkPacket r=new NetworkPacket(KAS_CST.FAIL);
                    r.add(KTGS_CST.MSG, KTGS_CST.OPNOTPERMITTED);
                    gsocket.Send(r);
            }
        }
    }

    private void loadKeys() throws IOException, ClassNotFoundException, 
            NoSuchChiffrementException, NoSuchCleException, NoSuchAlgorithmException, 
            NoSuchProviderException {
        //récupère la clé du serveur TGS
        ktgs=KeySerializator.loadKey(KEY_FILE, algorithm);
        
        //récupère et crée si nécessaire la clé du serveur (pour la copier coller après :p)
        ks=KeySerializator.getKey(SERVERKEY_FILE, algorithm);
        
        //initialise les objets chiffrements
        ch_ktgs=(Chiffrement) CryptoManager.newInstance(algorithm);
        ch_ktgs.init(ktgs);
        ch_ks=(Chiffrement) CryptoManager.newInstance(algorithm);
        ch_ks.init(ks);
    }

    public void stop() {
        this.quit=true;
    }
}
