package main;

import GestionSocket.GestionSocket;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.DiffieHellman.DHServer;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import Network.Constants.Server_Cle_constants;
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
import Network.Request;
import ServeurCle.SC_Init;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchProviderException;
/*
 * @author Julien
 * Représente le Serveur_Clé que contact l'Application_Admin pour avoir sa clé long terme 
 * Pour communiquer avec le client.
 * Un client se connecte et ils font envoie DH pour faire un DiffieHellman, si exception pdnt 
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
            EXT=".key",
            KEY_TYPE="DES";
    
    //variables membres
    private Properties config, users;
    private boolean quit;
    private int port;
    private String provider, algorithm, cipherMode, padding;
    private DHServer dh;
    private SC_State actualState;
    private SecurePasswordSha256 sp;
    public Serveur_Cle() {
        try {
            this.quit=false;
            this.sp = new SecurePasswordSha256();
            
            loadConfig();
        } catch (Exception ex) {
            System.err.printf("[SERVEUR_CLE] Exception %s : %s\n", 
                    ex.getClass().toString(), ex.getMessage());
            
            if(ex instanceof IOException) { //si un des fichiers properties pas trouvé
                usage_file();
            } else if(ex instanceof NumberFormatException) { //attribut port pas trouvé
                usage_config();
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
        System.out.printf("Le fichier %s doit comporter les Clés-Valeurs: port, keystore, "
                + "kspwd, algorithm, cipher, padding\n", CONFIG_FILE);
    }
    
    public static void main(String[] args) {
        Serveur_Cle sc=new Serveur_Cle();
    }

    private void startListening() throws IOException {
        ServerSocket ss=new ServerSocket(port);
        System.out.printf("[SERVER]Launched! waiting for client\n");
        Socket clientSocket=ss.accept();
        System.out.printf("[SERVER] client connected: %s:%d\n", 
                clientSocket.getInetAddress().toString(), clientSocket.getPort());
        
        GestionSocket gs=new GestionSocket(clientSocket);
        this.actualState=new SC_Init(gs, this);
        
        while(!quit) {
            Request req=(Request) gs.Receive();
            if(req==null) {
                break;
            }
            switch(req.getType()) {
                case Server_Cle_constants.DH: System.out.println("[SERVER] DH request received");
                    actualState.instantiate_DH(req);
                    break;
                case Server_Cle_constants.DHPK: System.out.println("[SERVER]DHPK request received");
                    actualState.DH_SetPublicKey(req);
                    break;
                case Server_Cle_constants.GETKEY:  System.out.println("[SERVER]GET KEY received"); 
                    actualState.get_key(req);
                    break;
                default: actualState.OperationNotPermitted(String.valueOf(req.getType()));
            }
        }
        
    }
    
    public void stopListening() {
        this.quit=true;
    }

    /**
     * @param dh the dh to set
     */
    public void setDh(DHServer dh) {
        this.dh = dh;
    }

    /**
     * @param key the key to set
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws java.security.InvalidKeyException
     */
    public void setDHKey(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException, 
            InvalidAlgorithmParameterException, InvalidKeyException {
        this.dh.setPublicKey(key);
    }

    /**
     * @return the dh
     */
    public DHServer getDh() {
        return dh;
    }

    /**
     * @param actualState the actualState to set
     */
    public void setActualState(SC_State actualState) {
        this.actualState = actualState;
    }

    /**
     * @return the algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * @return the cipherMode
     */
    public String getCipherMode() {
        return cipherMode;
    }

    /**
     * @return the padding
     */
    public String getPadding() {
        return padding;
    }

    private void loadConfig() throws NoSuchFieldException, IOException {
        //Check if properties exists
        this.config=new Properties();
        this.users=new Properties();

        this.config.load(new FileInputStream(CONFIG_FILE));
        this.users.load(new FileInputStream(USERS_FILE));
            
        this.port=Integer.valueOf(config.getProperty("port"));
        this.provider=config.getProperty("provider");
        this.algorithm=config.getProperty("algorithm");
        this.cipherMode=config.getProperty("cipher");
        this.padding=config.getProperty("padding");
        
        if(provider==null || cipherMode==null ||
                algorithm==null || padding==null) {
            throw new NoSuchFieldException();
        }
    }

    private Cle loadKey(String filename) throws FileNotFoundException, IOException, ClassNotFoundException {
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(filename));
        Cle c=(Cle) ois.readObject();
        ois.close();
        return c;
    }
    
    private Cle createKey(String username) throws NoSuchChiffrementException, IOException, 
            NoSuchCleException, NoSuchAlgorithmException, NoSuchProviderException {
        Cle k = (Cle) CryptoManager.genereCle(KEY_TYPE);
        ((CleDES)k).generateNew();
        
        ObjectOutputStream oos=new ObjectOutputStream(new FileOutputStream(username+EXT));
        oos.writeObject(k);
        oos.close();
        return k;
    }
    
    public Cle getKey(String keyUser) throws IOException, ClassNotFoundException, NoSuchProviderException,
            NoSuchChiffrementException, NoSuchCleException, NoSuchAlgorithmException {
        Cle c;
        try {
            c=this.loadKey(DIRECTORY+keyUser+EXT);
        } catch(FileNotFoundException e) {
            //fichier non trouvé=il faut la créer puis la sauvegarder
            c=this.createKey(DIRECTORY+keyUser+EXT);
        } 
        
        return c;
    }
    
    
    public boolean connectUser(String username, String salt, String receivedPassword) throws IOException {
        boolean passwordMatch=false;
        try {
            String password=users.getProperty(username); //retourne NULL si le user n'existe pas
            this.sp = new SecurePasswordSha256();
            this.sp.setSalt(salt);
            this.sp.generate(password);
            if(sp.verify(receivedPassword)) { //si les SHA256 des pwd match=> OK
                passwordMatch=true;
            }
        } catch(NullPointerException e) { //si user n'existe pas!
        }
        
        return passwordMatch;
    }
}
