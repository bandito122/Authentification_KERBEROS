/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Kerberos;

/**
 *
 * @author bobmastrolilli
 */
public interface KS_CST
{
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
