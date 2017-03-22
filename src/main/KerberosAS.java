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

/*
 * @author Julien
 * ATTENTION: CE SERVEUR PRODUIT LA CLE LONG TERME DU SERVEUR TGS :
 * C/C LE FICHIER USERNAME.SERVERKEY VERS LE DOSSIER KERBEROS_TGS/KTGS.KEY
 */
public class KerberosAS {
    private static final String DIRECTORY=System.getProperty("user.home")+ System.getProperty("file.separator")+
        "kerberos_as"+ System.getProperty("file.separator"),  
        CONFIG_FILE=DIRECTORY+"config.properties", USERS_FILE=DIRECTORY+"users.properties",
            TGSERVERS_FILE=DIRECTORY+"tgservers.properties", EXT=".key",
            SERVER_EXT=".serverkey";
    
    private static final int VERSION=1;
    private static final String ENCODING="UTF-8";
    private static final long VALIDITY_DAY=1;
    
    private Properties config, users,tgServer;
    private boolean quit;
    private int port;
    private String provider, algorithm, cipherMode, padding;
    private SecurePasswordSha256 sp;
    private GestionSocket gsocket;
    
    public KerberosAS() {
        try {
            loadConfig();
            startListening();
        } catch (IOException | NoSuchFieldException | NoSuchPaddingException ex) {
            Logger.getLogger(KerberosAS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static void main(String[] args) {
        KerberosAS kAS=new KerberosAS();
    }

    private void loadConfig() throws IOException, NoSuchFieldException {
        //Check if properties exists
        config=new Properties();
        users=new Properties();
        tgServer=new Properties();
        
        config.load(new FileInputStream(CONFIG_FILE));
        users.load(new FileInputStream(USERS_FILE));
        tgServer.load(new FileInputStream(TGSERVERS_FILE));
        
        String s_port=config.getProperty("port");
        algorithm=config.getProperty("algorithm");
        cipherMode=config.getProperty("cipher");
        padding=config.getProperty("padding");
        provider=config.getProperty("provider");
        if(algorithm==null || cipherMode==null || provider==null || padding==null || s_port==null) {
            throw new NoSuchFieldException();
        }
        
        port=Integer.valueOf(s_port);
    }
    
    public static void usage_file() {
        System.out.printf("Les fichiers de configuration %s et %s doivent se trouver dans le "
                + "dossier %s\n", CONFIG_FILE, USERS_FILE, DIRECTORY);
    }
    
    public static void usage_config() {
        System.out.printf("Le fichier %s doit comporter les Clés-Valeurs: port, "
                + "algorithm, cipher, padding\n", CONFIG_FILE);
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
    
    public String getTGServer(String commonName) {         
        return tgServer.getProperty(commonName);
    }
    
    private void startListening() throws IOException, NoSuchPaddingException {
        ServerSocket ss=new ServerSocket(port);
        System.out.printf("[KERBEROS AS]Launched! waiting for client\n");
        Socket clientSocket=ss.accept();
        System.out.printf("[KERBEROS AS] client connected: %s:%d\n", 
                    clientSocket.getInetAddress().toString(), clientSocket.getPort());

            gsocket=new GestionSocket(clientSocket);
        while(!quit) {
            NetworkPacket req=(NetworkPacket) gsocket.Receive();
            if(req==null) {
                break;
            }
            switch(req.getType()) {
                case KAS_CST.INIT: 
                    System.out.println("[KERBEROS AS] INIT request received");
                    this.handleInit(req);
                    break;
                case KAS_CST.QUIT:
                    System.out.println("[KERBEROS AS] QUIT request received");
                    gsocket.Close();
                    quit=true;
                    break;
                default:
                    NetworkPacket r=new NetworkPacket(KAS_CST.FAIL);
                    r.add(KAS_CST.MSG, KAS_CST.UNKNOWN_OPERATION);
                    //gsocket.Send(r);
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
            String tgServerAddr=getTGServer((String) r.get(KAS_CST.TGSNAME));
            boolean isConnected=connectUser((String) r.get(KAS_CST.USERNAME), 
                    (String) r.get(KAS_CST.SALT), (String) r.get(KAS_CST.PWD));
            boolean tgsFound=tgServerAddr!=null;
            
            System.out.printf("[KerberosAS]Tentative de connexion:\n\t Username: %s, Hash PWD %s\n"
                    + "\t IP: %s Serveur à atteindre: %s Valeur temporelle: %s\n", 
                    (String) r.get(KAS_CST.USERNAME), (String) r.get(KAS_CST.PWD), 
                    r.get(KAS_CST.INTERFACE), r.get(KAS_CST.TGSNAME), 
                    (String) r.get(KAS_CST.DATETIME));
            
            if(isConnected && tgsFound) {
                //les hashed parameters sont identiques
                reponse.setType(KAS_CST.YES);
                
                //récupère la clé long terme du client correspondant
                Kc=KeySerializator.getKey(
                        DIRECTORY+(String) r.get(KAS_CST.USERNAME)+EXT, algorithm);
                
                //génère une clé temporaire qui va permettre au client 
                //et au TGS de communiquer de manière sécurisée
                Kctgs= (CleDES)(Cle)CryptoManager.genereCle(algorithm);
                if(Kctgs instanceof CleDES) //obliger ici
                    ((CleDES)Kctgs).generateNew();
                
                Chiffrement chKc=(Chiffrement) CryptoManager.newInstance(algorithm);
                chKc.init(Kc);
                CipherGestionSocket cgs=new CipherGestionSocket(null, chKc);
                //construit la première partie du paquet, à savoir:
                //{La clé de session,version,nom du serveur TGS} 
                //chiffré avec la clé long terme du client Kc
                reponse.add(KAS_CST.KCTGS, cgs.crypte(Kctgs));
                reponse.add(KAS_CST.VERSION, cgs.crypte((Integer)VERSION));
                reponse.add(KAS_CST.TGSNAME, cgs.crypte(tgServerAddr));
                reponse.add(KAS_CST.DATETIME, LocalDate.now());
                
                //récupère la clé du serveur avec ce client et crypte le ticket avec
                Ktgs=KeySerializator.getKey(
                        DIRECTORY+(String) r.get(KAS_CST.USERNAME)+SERVER_EXT, algorithm);
                
                //deuxieme partie de la réponse: le ticket TGS
                //{nom du client, son ip, validité du ticket, cle de session}
                // chiffré avec la clé du serveur
                TicketTGS ticketTGS=new TicketTGS((String)r.get(KAS_CST.USERNAME), 
                        (String) r.get(KAS_CST.INTERFACE),
                        LocalDate.now().plusDays(VALIDITY_DAY), Kctgs); //définir la validité... 24h?
                
                //pour chiffrer le tciket TGS avec la clé du serveur TGS
                Chiffrement chKtgs=(Chiffrement) CryptoManager.newInstance(algorithm);
                chKtgs.init(Ktgs);
                cgs=new CipherGestionSocket(null, chKtgs);
                reponse.add(KAS_CST.TICKETGS, cgs.crypte(ticketTGS));                
                System.out.println("[KERBEROS AS]successful!");
            } else { // si user pas connected où si serveur tgs demandé pas trouvé: accès refusé
                reponse.setType(KAS_CST.NO);
                if(!isConnected) {//clé d'utilisateur pas trouvé
                    reponse.add(KAS_CST.MSG, KAS_CST.USERNAME_NOT_FOUND);
                    System.err.printf("[KERBEROS AS]Username: %s : %s\n", 
                            (String)r.get(KAS_CST.USERNAME), 
                            KAS_CST.USERNAME_NOT_FOUND);
                } else if(!tgsFound) { //serveur tgs pas trouvé
                    reponse.add(KAS_CST.MSG, KAS_CST.TGS_NOT_FOUND);
                    System.err.printf("[KERBEROS AS]Targetted TGS: %s : %s\n",
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
            reponse.add(KAS_CST.MSG, KAS_CST.FAILURE+" : "+ex.getMessage());
        } finally {            
            gsocket.Send(reponse);
        }
        
    }
}
