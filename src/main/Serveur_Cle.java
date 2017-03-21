package main;
import JavaLibrary.Crypto.ChiffreImpl.ChiffreDES;
import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.DiffieHellman.DiffieHellman;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import JavaLibrary.Network.GestionSocket;
import JavaLibrary.Network.NetworkPacket;
import ServeurCle.SC_State;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;
import ServeurCle.SC_Init_State;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchProviderException;
import ServeurCle.SC_CST;
import javax.crypto.SecretKey;
/*
 * @author Julien
 * Représente le Serveur_Clé que contact l'Application_Admin pour avoir sa clé long terme 
 * Pour communiquer avec le client.
 * Un client se connecte et ils font envoie DiffieHellman pour faire un DiffieHellman, si exception pdnt 
 * celui-ci renvoie un FAIL et ferme la socket.
 * Un client envoit une demande GETKEY pour récupéré la clé correspondant au username associé 
 * d'un pwd envoyés en paramètre, si autre demande => renvoyer FAIL (signale une ERREUR:
 * commande non supportée  et ferme la socket. 
 * Le username et password du client correspondent respectivement à l'alias et le storepasse de 
 * la clé secrète stockée dans le fichier!
 * Si GETKEY réussit: le serveur répond: YES avec la clé long terme correspondant au SHA1
 *                  si clé pas trouvée: FAIL: key not found
 * si login échoue: NO: passphrase not correct
 * et ferme la socket dans TOUS les cas. Puis il se remet en attente d'une connexion.
 */
public class Serveur_Cle {
    //constantes fichiers
    private static final String DIRECTORY=System.getProperty("user.home")+ System.getProperty("file.separator")+
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
    
    //charge une clé secrète à partir d'un fichier
    private Cle loadKey(String username) throws FileNotFoundException, IOException, ClassNotFoundException {
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(DIRECTORY+username+EXT));
        Cle c=(Cle) ois.readObject();
        ois.close();
        return c;
    }
    
    //crée une clé secrète et l'enregistre dans un fichier
    private Cle createKey(String username) throws NoSuchChiffrementException, IOException, 
            NoSuchCleException, NoSuchAlgorithmException, NoSuchProviderException {
        Cle k = (Cle) CryptoManager.genereCle(algorithm);
        ((CleDES)k).generateNew();        
        ObjectOutputStream oos=new ObjectOutputStream(new FileOutputStream(DIRECTORY+username+EXT));
        oos.writeObject(k);
        oos.close();
        return k;
    }
    
    //permet de récupérer la clé d'un utilisateur
    //le format du nom de fichier est "username.key"
    public Cle getKey(String keyUser) throws IOException, ClassNotFoundException, NoSuchProviderException,
            NoSuchChiffrementException, NoSuchCleException, NoSuchAlgorithmException {
        Cle c;
        try {
            c=loadKey(keyUser); //si la clé existe, on la charge à partir du fichier
        } catch(FileNotFoundException e) {
            //fichier non trouvé=il faut la créer puis la sauvegarder
            c=createKey(keyUser);
        } 
        
        return c;
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
    
    public static void main(String[] args) {
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