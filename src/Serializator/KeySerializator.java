package Serializator;

import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CleImpl.CleDES;
import JavaLibrary.Crypto.CryptoManager;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/*
 * @author Julien
 */
public class KeySerializator {
    
    public static void saveKey(String path, Cle cle) throws IOException {
        ObjectOutputStream oos=new ObjectOutputStream(new FileOutputStream(path));
        oos.writeObject(cle);
        oos.flush();
        oos.close();
    }
    
    public static Cle loadKey(String path, String algorithm) throws FileNotFoundException, IOException, ClassNotFoundException {
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(path));
        Cle c=(Cle) ois.readObject();
        ois.close();
        return c;
    }
    
    public static Cle createKey(String path, String algorithm) throws NoSuchChiffrementException, IOException, 
            NoSuchCleException, NoSuchAlgorithmException, NoSuchProviderException {
        Cle c = (Cle) CryptoManager.genereCle(algorithm);
        ((CleDES)c).generateNew();
        
        saveKey(path, c);
        
        return c;
    }
    
    //récupère la server key pour le serveur TGS
    public static Cle getKey(String path, String algorithm) throws IOException, 
            ClassNotFoundException, NoSuchChiffrementException, 
            NoSuchCleException, NoSuchAlgorithmException, NoSuchProviderException {
        Cle c;
        try {
            c=loadKey(path,algorithm);
        } catch(FileNotFoundException e) {
            //fichier non trouvé=il faut la créer puis la sauvegarder
            c=createKey(path,algorithm);
        } 
        
        return c;
    }
}
