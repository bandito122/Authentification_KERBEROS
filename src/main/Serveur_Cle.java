package main;

import DiffieHellman.DHServer;
import GestionSocket.GestionSocket;
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
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
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
    private static final String DIRECTORY="~/server_cle/",  
            CONFIG_FILE=DIRECTORY+"config.properties", USERS_FILE=DIRECTORY+"users.properties";
    
    //variables membres
    private Properties config, users;
    private boolean quit;
    private int port;
    private String provider, algorithm, cipherMode, padding,ksName, ksPwd, ksType;
    private DHServer dh;
    private SC_State actualState;
    private KeyStore ks;
    
    public Serveur_Cle() {
        try {
            this.quit=false;
            loadConfig();
            loadKeystore();
            
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
        Socket clientSocket=ss.accept();
        System.out.printf("[SERVER] client connected: %s:%d\n", 
                clientSocket.getInetAddress().toString(), clientSocket.getPort());
        
        GestionSocket gs=new GestionSocket(clientSocket);
        
        while(!quit) {
            Request req=(Request) gs.Receive();
            switch(req.getType()) {
                case Server_Cle_constants.DH: actualState.instantiate_DH(req);
                    break;
                case Server_Cle_constants.DHPK: actualState.DH_SetPublicKey(req);
                    break;
                case Server_Cle_constants.GETKEY: actualState.get_key(req);
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
    
    public KeyStore getKeyStore() { 
        return this.ks; 
    }

    private void loadConfig() throws NoSuchFieldException, IOException {
        //Check if properties exists
        this.config=new Properties();
        this.users=new Properties();

        this.config.load(new FileInputStream(CONFIG_FILE));
        this.users.load(new FileInputStream(USERS_FILE));
            
        this.port=Integer.valueOf(config.getProperty("port"));
        this.provider=config.getProperty("provider");
        this.ksName=config.getProperty("keystore");
        this.ksPwd=config.getProperty("kspwd");
        this.ksType=config.getProperty("ksType");
        this.algorithm=config.getProperty("algorithm");
        this.cipherMode=config.getProperty("cipher");
        this.padding=config.getProperty("padding");
        
        if(ksName==null || ksPwd==null || ksType==null || provider==null || getCipherMode()==null ||
                getAlgorithm()==null || getPadding()==null) {
            throw new NoSuchFieldException();
        }
    }

    private void loadKeystore() throws KeyStoreException, NoSuchProviderException, 
            FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks=KeyStore.getInstance(ksType, provider);
        ks.load(new FileInputStream(ksName), ksPwd.toCharArray());
    }

}
