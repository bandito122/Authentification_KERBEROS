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
import Kerberos.ASSTATE.AS_Authentication_State;
import Kerberos.ASSTATE.AS_State;
import Kerberos.TicketTGS;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDate;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;
import Kerberos.KAS_CST;
import Serializator.KeySerializator;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*
 * @author Julien
 * ATTENTION: CE SERVEUR PRODUIT LA CLE LONG TERME DU SERVEUR TGS :
 * C/C LE FICHIER USERNAME.SERVERKEY VERS LE DOSSIER KERBEROS_TGS/KTGS.KEY
 */
public class KerberosAS 
{
    private static final String FS=System.getProperty("file.separator");
    public String DIRECTORY = System.getProperty("user.home") + 
            FS+ "kerberos_as"+ FS;
    //mettre certains trucs dans le fichier de configuration
    private String CONFIG_FILE = DIRECTORY+"config.properties",
                USERS_FILE = DIRECTORY+"users.properties",
                TGSERVERS_FILE = DIRECTORY+"tgservers.properties",
                EXT = ".key", SERVER_EXT = ".serverkey";

    private Properties config, users, tgServer;
    private boolean quit;
    private int port, version;
    private long validite;
    private String algorithm, encoding;
    private SecurePasswordSha256 sp;
    private GestionSocket gsocket;
    private AS_State state;
    
    public KerberosAS() {
        try {
            loadConfig();
            startListening();
        } catch (IOException | NoSuchFieldException | NoSuchPaddingException ex) {
            Logger.getLogger(KerberosAS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static void main(String[] args) 
    {
        Security.addProvider(new BouncyCastleProvider());
        KerberosAS kAS=new KerberosAS();
    }

    private void loadConfig() throws IOException, NoSuchFieldException 
    {
        //Check if properties exists
        config=new Properties();
        users=new Properties();
        tgServer=new Properties();
        
        getConfig().load(new FileInputStream(getCONFIG_FILE()));
        getUsers().load(new FileInputStream(getUSERS_FILE()));
        getTgServer().load(new FileInputStream(getTGSERVERS_FILE()));
        
        String s_port=getConfig().getProperty("port");
        System.out.println("getconfigFile = " + getCONFIG_FILE());
        String s_validite=getConfig().getProperty("validite");
        String s_version=getConfig().getProperty("version");
        algorithm=getConfig().getProperty("algorithm");
        encoding=getConfig().getProperty("encoding");
        
        if(getAlgorithm()==null || s_port==null || s_validite==null || s_version==null || encoding==null) {
            throw new NoSuchFieldException();
        }
        
        port=Integer.valueOf(s_port);
        version=Integer.valueOf(s_version);
        validite=Long.valueOf(s_validite);
    }
    
    public void usage_file() {
        System.out.printf("Les fichiers de configuration %s et %s doivent se trouver dans le "
                + "dossier %s\n", getCONFIG_FILE(), getUSERS_FILE(), getDIRECTORY());
    }
    
    public void usage_config() {
        System.out.printf("Le fichier %s doit comporter les Clés-Valeurs: port, "
                + "algorithm, cipher, padding\n", getCONFIG_FILE());
    }
    
    public boolean connectUser(String username, String salt, String receivedPassword) throws IOException {
        boolean passwordMatch=false;
        try {
            String password=getUsers().getProperty(username); //retourne NULL si le user n'existe pas
            this.sp = new SecurePasswordSha256();
            this.getSp().setSalt(salt);
            this.getSp().generate(password);
            if(getSp().verify(receivedPassword)) { //si les SHA256 des pwd match=> OK
                passwordMatch=true;
            }
        } catch(NullPointerException e) { //si user n'existe pas!
        }
        
        return passwordMatch;
    }
    
    private void startListening() throws IOException, NoSuchPaddingException 
    {
        ServerSocket ss=new ServerSocket(getPort());
        System.out.printf("[KERBEROS AS]Launched! waiting for client\n");
        Socket clientSocket=ss.accept();
        System.out.printf("[KERBEROS AS] client connected: %s:%d\n", 
                    clientSocket.getInetAddress().toString(), clientSocket.getPort());

        setGsocket(new GestionSocket(clientSocket));
        state=new AS_Authentication_State(gsocket, this);
        
        while(!isQuit()) {
            NetworkPacket req=(NetworkPacket) getGsocket().Receive();
            if(req==null) {
                System.out.println("null packet received");
                break;
            }
            switch(req.getType()) {
                case KAS_CST.INIT: 
                    System.out.println("[KERBEROS AS] INIT request received");
                    //this.handleInit(req);
                    state.HandleAuthentication(req);
                    break;
                case KAS_CST.TRANSFER_KEY:
                     state.HandleTransferKey(req);
                    break;
                case KAS_CST.QUIT:
                    System.out.println("[KERBEROS AS] QUIT request received");
                    state.HandleQuit(req);
                    //getGsocket().Close();
                    quit=true;
                    break;
                default:
                    NetworkPacket r=new NetworkPacket(KAS_CST.FAIL);
                    r.add(KAS_CST.MSG, KAS_CST.UNKNOWN_OPERATION);
                    getGsocket().Send(r);
            }
        }
        System.out.println("[KERBEROS AS]Bye bye!");
    }

    private void handleInit(NetworkPacket r) throws NoSuchPaddingException {
        //récupérer les paramètres
        Cle Kc, Kctgs, Ktgs;
        NetworkPacket reponse=new NetworkPacket(0);
        try {            
            //authentifier le client + regarder si le serveur demandé existe
            String tgServerAddr=getTgServer().getProperty((String) r.get(KAS_CST.TGSNAME));
            boolean isConnected=connectUser((String) r.get(KAS_CST.USERNAME), 
                    (String) r.get(KAS_CST.SALT), (String) r.get(KAS_CST.PWD));
            boolean tgsFound=tgServerAddr!=null;
            
            System.out.printf("[KerberosAS]Tentative de connexion:\n\t Username: %s, Hash PWD %s\n"
                    + "\t IP: %s Serveur à atteindre: %s Valeur temporelle: %s\n", 
                    r.get(KAS_CST.USERNAME).toString(), (String) r.get(KAS_CST.PWD).toString(), 
                    r.get(KAS_CST.INTERFACE).toString(), r.get(KAS_CST.TGSNAME).toString(), 
                    r.get(KAS_CST.DATETIME).toString());
            
            if(isConnected && tgsFound) {
                //les hashed parameters sont identiques
                reponse.setType(KAS_CST.YES);
                
                //récupère la clé long terme du client correspondant
                Kc=KeySerializator.getKey(getDIRECTORY()+(String) r.get(KAS_CST.USERNAME)+getEXT(), getAlgorithm());
                
                //génère une clé temporaire qui va permettre au client 
                //et au TGS de communiquer de manière sécurisée
                Kctgs= (CleDES)(Cle)CryptoManager.genereCle(getAlgorithm());
                if(Kctgs instanceof CleDES) //obliger ici
                    ((CleDES)Kctgs).generateNew();
                
                Chiffrement chKc=(Chiffrement) CryptoManager.newInstance(getAlgorithm());
                chKc.init(Kc);
                CipherGestionSocket cgs=new CipherGestionSocket(null, chKc);
                //construit la première partie du paquet, à savoir:
                //{La clé de session,version,nom du serveur TGS} 
                //chiffré avec la clé long terme du client Kc
                reponse.add(KAS_CST.KCTGS, cgs.crypte(Kctgs));
                reponse.add(KAS_CST.VERSION, cgs.crypte((Integer)getVersion()));
                reponse.add(KAS_CST.TGSNAME, cgs.crypte(tgServerAddr));
                reponse.add(KAS_CST.DATETIME, LocalDate.now());
                
                //récupère la clé du serveur avec ce client et crypte le ticket avec
                Ktgs=KeySerializator.getKey(getDIRECTORY()+(String) r.get(KAS_CST.USERNAME)+getSERVER_EXT(), getAlgorithm());
                
                //deuxieme partie de la réponse: le ticket TGS
                //{nom du client, son ip, validité du ticket, cle de session}
                // chiffré avec la clé du serveur
                TicketTGS ticketTGS=new TicketTGS((String)r.get(KAS_CST.USERNAME), 
                        (String) r.get(KAS_CST.INTERFACE),
                        LocalDate.now().plusDays(getValidite()), Kctgs); //définir la validité... 24h?
                
                //pour chiffrer le tciket TGS avec la clé du serveur TGS
                Chiffrement chKtgs=(Chiffrement) CryptoManager.newInstance(getAlgorithm());
                chKtgs.init(Ktgs);
                cgs=new CipherGestionSocket(null, chKtgs);
                reponse.add(KAS_CST.TICKETGS, cgs.crypte(ticketTGS));                
                System.out.println("[KERBEROS AS]successful!");
            } else { // si user pas connected où si serveur tgs demandé pas trouvé: accès refusé
                reponse.setType(KAS_CST.NO);
                if(!isConnected) { //clé d'utilisateur pas trouvé
                    reponse.add(KAS_CST.MSG, KAS_CST.USER_NOT_FOUND);
                    System.err.printf("[KERBEROS AS]Username pas trouvé: %s : %s\n", 
                            (String)r.get(KAS_CST.USERNAME), 
                            KAS_CST.USER_NOT_FOUND);
                } else if(!tgsFound) { //serveur tgs demandé pas trouvé
                    reponse.add(KAS_CST.MSG, KAS_CST.TGS_NOT_FOUND);
                    System.err.printf("[KERBEROS AS]Targeted TGS pas trouvé: %s : %s\n",
                            (String) r.get(KAS_CST.TGSNAME), 
                            KAS_CST.TGS_NOT_FOUND);
                }
            }
        }
        catch (IOException | ClassNotFoundException | NoSuchProviderException | 
                NoSuchChiffrementException | NoSuchCleException | 
                NoSuchAlgorithmException | NullPointerException 
                ex) {
            Logger.getLogger(KerberosAS.class.getName()).log(Level.SEVERE, null, ex);
            reponse.setType(KAS_CST.FAIL);
            reponse.add(KAS_CST.MSG, KAS_CST.FAILURE+ex.getMessage());
        } finally {            
            getGsocket().Send(reponse);
        }       
    }

    public Properties getConfig() {
        return config;
    }

    public Properties getUsers() {
        return users;
    }

    public Properties getTgServer() {
        return tgServer;
    }

    public boolean isQuit() {
        return quit;
    }

    public int getPort() {
        return port;
    }

    public int getVersion() {
        return version;
    }

    public long getValidite() {
        return validite;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public SecurePasswordSha256 getSp() {
        return sp;
    }

    public GestionSocket getGsocket() {
        return gsocket;
    }

    public void setGsocket(GestionSocket gsocket) {
        this.gsocket = gsocket;
    }
    
    public String getDIRECTORY() {
        return DIRECTORY;
    }

    public String getCONFIG_FILE() {
        return CONFIG_FILE;
    }

    public  String getUSERS_FILE() {
        return USERS_FILE;
    }

    public String getTGSERVERS_FILE() {
        return TGSERVERS_FILE;
    }

    public String getEXT() {
        return EXT;
    }

    public String getSERVER_EXT() {
        return SERVER_EXT;
    }
    
    public void setState(AS_State state) {
        this.state=state;
    }
    
    public String getEncoding() {
        return encoding;
    }
}
