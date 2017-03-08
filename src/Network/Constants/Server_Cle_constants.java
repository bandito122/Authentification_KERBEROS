package Network.Constants;

/*
 * @author Julien
 */

public interface Server_Cle_constants {
    //constantes opérations
    public static int FAIL=-1, GETKEY=0, YES=1, NO=2, DH=3, DHPK=4;
    
    //constantes messages
    public static final String LOGINFAILED="passephrase de passe incorrect",
            CMDFAILED="commande non-supportée", DHFAILED="erreur pendant le DiffieHellman",
            //faire un String.format avant
            KEYFAIL="Clé long terme pas trouvée où clé invalide",
            OPNOTPERMITTED="ERROR: opération %s interdite "; 
}
