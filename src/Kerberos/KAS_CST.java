package Kerberos;

/**
 *
 * @author Julien
 */
public interface KAS_CST {
    //constantes opérations
    public static int FAIL=-1 //erreur interne au KerberosAS
            , YES=1, NO=2 /*refus d'accès*/, INIT=3, QUIT=4;
    
    //messages d'erreurs constants
    public static final String USER_NOT_FOUND="utilisateur inconnu", 
            TGS_NOT_FOUND="le TGS demandé est introuvable",
            UNKNOWN_OPERATION="opération inconnue",
            FAILURE="erreur interne au serveur :";
   
    //constantes des noms des paramètres
    public static final String MSG="message", USERNAME="username", PWD="pwd", SALT="salt",
            INTERFACE="interface", TGSNAME="tgsname", DATETIME="datetime", KCTGS="kctgs",
            VERSION="version", TICKETGS="ticketgs";
    
}
