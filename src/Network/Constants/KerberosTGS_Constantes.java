/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Network.Constants;

/**
 *
 * @author Julien
 */
public interface KerberosTGS_Constantes {
     //constantes opérations
    public static int FAIL=-1, YES=1, NO=2, INIT=3;
    
    //messages d'erreurs constants
    public static final String LOGINFAILED="passephrase de passe incorrect",
            CMDFAILED="commande non-supportée", DHFAILED="erreur pendant le DiffieHellman",
            //faire un String.format avant
            KEYFAIL="Clé long terme pas trouvée où clé invalide",
            OPNOTPERMITTED="ERROR: opération %s interdite "; 
}
