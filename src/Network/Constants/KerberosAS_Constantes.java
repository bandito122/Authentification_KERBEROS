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
public interface KerberosAS_Constantes {
    //constantes opérations
    public static int FAIL=-1 //erreur interne au KerberosAS
            , YES=1, NO=2 /*refus d'accès*/, INIT=3, QUIT=4;
    
    //messages d'erreurs constants
    public static final String USERNAME_NOT_FOUND="", TGS_NOT_FOUND="le TGS demandé est introuvable",
            UNKNOWN_OPERATION="opération inconnue",
            FAILURE="erreur interne au serveur";
    
}
