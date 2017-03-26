package Kerberos;

/*
 * @author Julien
 * En faire une classe contenant une config!!!
 */
public interface KTGS_CST {
     //constantes opérations
    public static int FAIL=-1, YES=1, NO=2, SEND_AUTHENTICATOR=3, SEND_TICKET=4;
    
    //messages d'erreurs constants
    public static final String CMD_FAILED="commande non-supportée",
            DATETIME_FAILED="Authenticator est périmé",
            OPNOTPERMITTED="ERROR: opération %s interdite ",
            SUCCESS="succes"; 
    
    //constantes des noms des paramètres
    public static final String ACS="acs", TGS="tgs", SERVER_ADDR="server", KCS="kcs",
            VERSION="version", SERVER_NAME="servername", DATETIME="datetime", 
            TICKET_SERVER="ticketgs", USERNAME="username", MSG="msg";
}
