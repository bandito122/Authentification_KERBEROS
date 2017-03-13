package main;

import GestionSocket.GestionSocket;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import Kerberos.AuthenticatorCS;
import Kerberos.TicketTGS;
import Network.Constants.KerberosAS_Constantes;
import Network.Constants.KerberosTGS_Constantes;
import Network.Request;
import Utils.ByteUtils;
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

/*
 * @author Julien
 */
public class KerberosTGS {
    private static final String DIRECTORY=System.getProperty("user.home")+ System.getProperty("file.separator")+
        "kerberos_tgs"+ System.getProperty("file.separator"),  
        CONFIG_FILE=DIRECTORY+"config.properties", USERS_FILE=DIRECTORY+"users.properties", EXT=".serverkey",
            SERVER_EXT=".key",
            KEY_FILE=DIRECTORY+"tgs"+EXT,
            SERVERKEY_FILE=DIRECTORY+"default_serverkey"+SERVER_EXT;
    
    private static final int VERSION=2;
    private static String ENCODING="UTF-8";
    private static long VALIDITY_DAY=1;
    
    private Properties config, users;
    private boolean quit;
    private int port;
    private String provider, algorithm, cipherMode, padding, 
            transformation;
    private SecurePasswordSha256 sp;
    private GestionSocket gsocket;
    private String name;
    private Cle ktgs,kctgs, kcs, ks;
    
    public KerberosTGS(String name) {
        try {
            this.name=name;
            loadConfig();
            loadKey();
        } catch (IOException | NoSuchFieldException ex) {
            Logger.getLogger(KerberosAS.class.getName()).log(Level.SEVERE, null, ex);
            System.exit(-1);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
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
        this.config=new Properties();
        this.users=new Properties();
        
        this.config.load(new FileInputStream(CONFIG_FILE));
        this.users.load(new FileInputStream(USERS_FILE));
        
        String s_port=config.getProperty("port");
        this.algorithm=config.getProperty("algorithm");
        this.cipherMode=config.getProperty("cipher");
        this.padding=config.getProperty("padding");
        this.provider=config.getProperty("provider");
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
            Request req=(Request) gsocket.Receive();
            if(req==null) {
                break;
            }
            switch(req.getType()) {
                case KerberosTGS_Constantes.INIT: System.out.println("[KERBEROS TGS] INIT request received");
                    HandleInit(req);
                    break;
                default:
                    Request r=new Request(KerberosAS_Constantes.FAIL);
                    r.setChargeUtile(KerberosAS_Constantes.OPNOTPERMITTED);
                    gsocket.Send(r);
            }
        }
    }

    private void HandleInit(Request r) {
        ArrayList<Object> parameters=(ArrayList<Object>) r.getChargeUtile();
        try {
            //1er param=ACS
            Cipher cipher=Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, ((CleDES)ktgs).getCle());

            //Le serveur décrypte avec sa clé symétrique le ticket et en extrait la clé de session
            //2eme param=TGS
            TicketTGS ticketTGS=(TicketTGS) ByteUtils.toObject2(cipher.doFinal((byte[]) parameters.get(1)));
            kctgs=ticketTGS.cleSession;
            
             //la clé de session sert à déchiffer l'authentificateur 
            cipher.init(Cipher.DECRYPT_MODE, ((CleDES)kctgs).getCle());
            AuthenticatorCS acs=(AuthenticatorCS) ByteUtils.toObject2(cipher.doFinal((byte[]) parameters.get(0)));
            
            //il faudrait vérifier les informations reçues
            
            //Envoyer au client la réponse
            cipher.init(Cipher.ENCRYPT_MODE, ((CleDES)kctgs).getCle());
            ArrayList<Object> paramReponse=new ArrayList<>(2);
            ArrayList<Object> firstPart=new ArrayList<>(4);
            ArrayList<Object> secondPart=new ArrayList<>(4);
            Request reponse=new Request(KerberosTGS_Constantes.YES);
            
            //Chiffrer avec la clé de session Kc,tgs
            //générer une clé de session client-serveur
            kcs=CryptoManager.genereCle(algorithm);
            ((CleDES)kcs).generateNew();
            firstPart.add(cipher.doFinal(ByteUtils.toByteArray(kcs)));
            //envoyer la version
            ByteBuffer bb=ByteBuffer.allocate(4);
            bb.putInt(VERSION);
            firstPart.add(cipher.doFinal(bb.array()));
            //le nom du serveur à atteindre
            firstPart.add(cipher.doFinal("default".getBytes(ENCODING)));
            firstPart.add(cipher.doFinal(LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:00")).getBytes(ENCODING)));
            
            //Chiffrer avec la clé du serveur
            cipher.init(Cipher.ENCRYPT_MODE, ((CleDES)ks).getCle());
            ticketTGS=new TicketTGS(acs.client, "localhost:6004", LocalDateTime.now().plusDays(VALIDITY_DAY), kcs);
            secondPart.add(cipher.doFinal(ByteUtils.toByteArray(ticketTGS)));
            
            //ajouter les deux listes à la liste de paramètre de la réponse
            paramReponse.add(firstPart);
            paramReponse.add(secondPart);
            reponse.setChargeUtile(paramReponse);
            gsocket.Send(reponse);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException | 
                ClassNotFoundException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException | NoSuchCleException ex) {
            Logger.getLogger(KerberosTGS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void loadKey() throws IOException, ClassNotFoundException {
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(KEY_FILE));
        this.ktgs=(Cle) ois.readObject();
        ois.close();
        
        ois=new ObjectInputStream(new FileInputStream(SERVERKEY_FILE));
        this.ks=(Cle) ois.readObject();
        ois.close();
    }
}
