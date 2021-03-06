package main;
import JavaLibrary.Crypto.ChiffreImpl.ChiffreDES;
import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.DiffieHellman.DiffieHellman;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import ServeurCle.State.SC_State;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;
import ServeurCle.State.SC_Init_State;
import ServeurCle.SC_CST;
import java.security.Security;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
/*
 * @author Julien
 * ATTENTION: CE SERVEUR PRODUIT LA CLE LONG TERME DU CLIENT ET DU KERBEROS AS
 * C/C LE FICHIER USERNAME.KEY VERS LE DOSSIER KERBEROS_AS/USERNAME.KEY
 */
public class Serveur_Cle {
    //constantes fichiers
    public static final String DIRECTORY=System.getProperty("user.home")+ System.getProperty("file.separator")+
            "server_cle"+ System.getProperty("file.separator"),  
            CONFIG_FILE=DIRECTORY+"config.properties", USERS_FILE=DIRECTORY+"users.properties",
            EXT=".key";
    
    //variables membres
    private Properties config, users;
    private boolean quit;
    private int port;
    private String provider, algorithm, cipher, padding;
    private DiffieHellman dh;
    private SC_State actualState;
    private Chiffrement ch;
    public GestionSocket gs;
    
    public Serveur_Cle() {
        try {
            quit=false;            
            loadConfig();
        } catch (Exception ex) {
            System.err.printf("[SERVEUR_CLE] Exception %s : %s\n", 
                    ex.getClass().toString(), ex.getMessage());
            
            if(ex instanceof IOException) { //si un des fichiers properties pas trouvé
                usage_file();
            } else if(ex instanceof NoSuchFieldException) {
                usage_config();
            }
            System.exit(-1);
        }
        
        try {
            startListening();
        } catch (Exception ex) {
            System.err.printf("[SERVEUR_CLE] Exception %s : %s\n", 
                    ex.getClass().toString(), ex.getMessage());
            System.exit(-1);
        }
    }
    
    public static void usage_file() {
        System.out.printf("Les fichiers de configuration %s et %s doivent se trouver dans le "
                + "dossier %s\n", CONFIG_FILE, USERS_FILE, DIRECTORY);
    }
    
    public static void usage_config() {
        System.out.printf("Le fichier %s doit comporter les Clés-Valeurs: port,"
                + "provider, algorithm, cipher, padding\n", CONFIG_FILE);
    }
    
    private void startListening() throws IOException {
        ServerSocket ss=new ServerSocket(port);
        System.out.printf("[SERVER]Launched! waiting for client\n");
        Socket clientSocket=ss.accept();
        System.out.printf("[SERVER] client connected: %s:%d\n", 
                clientSocket.getInetAddress().toString(), clientSocket.getPort());
        
        gs=new GestionSocket(clientSocket);
        actualState=new SC_Init_State(gs, this);
        
        while(!quit) {
            NetworkPacket req=(NetworkPacket) gs.Receive();
            if(req==null) {
                break;
            }
            //dispatch les requêtes
            switch(req.getType()) {
                case SC_CST.INIT: System.out.println("[SERVER] DH request received");
                    actualState.init_step(req);
                    break;
                case SC_CST.DHPK: System.out.println("[SERVER]DHPK request received");
                    actualState.DHPK_step(req);
                    break;
                case SC_CST.GETKEY:  System.out.println("[SERVER]GET KEY received"); 
                    actualState.get_key(req);
                    break;
                default: actualState.OperationNotPermitted(String.valueOf(req.getType()));
            }
        }
    }
    
    public void stopListening() {
        this.quit=true;
    }
    
    private void loadConfig() throws NoSuchFieldException, IOException {
        //charge les paramètres de configuration
        config=new Properties();
        users=new Properties();
        config.load(new FileInputStream(CONFIG_FILE));
        users.load(new FileInputStream(USERS_FILE));
            
        String s_port=config.getProperty("port");
        algorithm=config.getProperty("algorithm");
        cipher=config.getProperty("cipher");
        padding=config.getProperty("padding");
        provider=config.getProperty("provider");
        
        //si un de ces paramètres est nul: impossible de continuer l'exécution du serveur
        if(algorithm==null || provider==null || cipher==null || padding==null 
                || s_port==null) {
            throw new NoSuchFieldException();
        }
        
        port=Integer.valueOf(s_port);
    }
    
    //permet de vérifier si un mot de passe à partir d'un username, un "salement"
    //de mot de passe envoyé par l'utilisateur et un password "digesté"
    public boolean connectUser(String username, String salt, String receivedPassword) 
            throws IOException {
        boolean passwordMatch=false;
        try {
            String password=users.getProperty(username); //retourne NULL si le user n'existe pas
            SecurePasswordSha256 sp = new SecurePasswordSha256();
            sp.setSalt(salt);
            sp.generate(password);
            if(sp.verify(receivedPassword)) { //si les SHA256 des pwd match=> OK
                passwordMatch=true;
            }
        } catch(NullPointerException e) { //si user n'existe pas!
        }
        
        return passwordMatch;
    }

    public void setDh(DiffieHellman dh) {
        this.dh = dh;
    }
    
    public DiffieHellman getDh() {
        return dh;
    }
    
    public void setDHKey(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException, 
            InvalidAlgorithmParameterException, InvalidKeyException {
        this.dh.setDHParam(key);
    }
    
    public void setActualState(SC_State actualState) {
        this.actualState = actualState;
    }
    
    public String getAlgorithm() {
        return algorithm;
    }
    
    public String getCipher() {
        return cipher;
    }

    public String getPadding() {
        return padding;
    }
    
    public static void main(String[] args) 
    {
        Security.addProvider(new BouncyCastleProvider());
        Serveur_Cle sc=new Serveur_Cle();
    }

    public Chiffrement getChiffrement() {
        return ch;
    }

    public void createChiffrement(SecretKey sk) throws NoSuchChiffrementException {
        ch=(ChiffreDES) CryptoManager.newInstance(getAlgorithm());
        ch.init(new CleDES(sk));
    }
}