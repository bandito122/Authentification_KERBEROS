package ServeurCle;

/*
 * @author Julien
 */

public interface SC_CST {
    //constantes opérations
    //NO= accès refusé et FAIL=Erreur
    public static int FAIL=-1, GETKEY=0, YES=1, NO=2, INIT=3, DHPK=4;
    
    //message constants pour erreurs
    public static final String LOGIN_FAILED="passephrase incorrect ",
            UNKOWN_OPERATION="commande %s non-supportée ", 
            DHFAILED="erreur pendant le DiffieHellman ",
            KEY_FAILED="Clé long terme pas trouvée où clé invalide ",
            OPNOTPERMITTED="ERROR: opération %s interdite "; 
    
    //constantes des noms des paramètres
    public static final String USERNAME="username", PWD="password", SALT="salt",
            MSG="message", PK="PK", SECRETKEY="secretkey";
}
