package ServeurCle;

import java.io.IOException;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * @author Julien
 */
public class Exemple_ClientCle {
    public static String HOST="localhost";
    public static int PORT=6001;
    public static void main(String[] args) {
        try {
            //SC doit écouter sur le port 6001
            Socket s=new Socket(HOST, PORT);
        } catch (IOException ex) {
            Logger.getLogger(Exemple_ClientCle.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
