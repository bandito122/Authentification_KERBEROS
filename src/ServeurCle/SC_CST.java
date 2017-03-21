package ServeurCle;

/*
 * @author Julien
 */

public interface SC_CST {
    //constantes opérations
    public static int FAIL=-1, GETKEY=0, YES=1, NO=2, INIT=3, DHPK=4;
    
    //message constants pour erreurs
    public static final String LOGINFAILED="passephrase de passe incorrect",
            CMDFAILED="commande non-supportée", DHFAILED="erreur pendant le DiffieHellman",
            //faire un String.format avant
            KEYFAILED="Clé long terme pas trouvée où clé invalide",
            OPNOTPERMITTED="ERROR: opération %s interdite "; 
    
    //constantes paramètres
    public static final String USERNAME="username", PWD="password", SALT="salt", MSG="message",
            PK="PK",SECRETKEY="secretkey";
}
