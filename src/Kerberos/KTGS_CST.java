/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Kerberos;

/*
 * @author Julien
 * En faire une classe contenant une config!!!
 */
public interface KTGS_CST {
     //constantes opérations
    public static int FAIL=-1, YES=1, NO=2, SENDTICKET=3, SENDACS=4;
    
    //messages d'erreurs constants
    public static final String LOGINFAILED="passephrase de passe incorrect",
            CMDFAILED="commande non-supportée", DHFAILED="erreur pendant le DiffieHellman",
            //faire un String.format avant
            KEYFAIL="Clé long terme pas trouvée où clé invalide",
            OPNOTPERMITTED="ERROR: opération %s interdite ",
            SUCCESS="succes"; 
    
    //constantes des noms des paramètres
    public static final String ACS="acs", TGS="tgs", SERVER_ADDR="server", KCS="kcs",
            VERSION="version", SERVER_NAME="servername", DATETIME="datetime", 
            TICKETGS="ticketgs", USERNAME="username", MSG="msg";
}
