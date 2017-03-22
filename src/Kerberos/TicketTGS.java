package Kerberos;


import JavaLibrary.Crypto.Cle;
import java.io.Serializable;
import java.time.LocalDate;

/*
 * @author Julien
 */
public class TicketTGS implements Serializable {
    //{nom du client, son ip, validité du ticket, 
    //cle de session} chiffré avec la clé du serveur
    public String client, ip;
    public LocalDate tv;
    public Cle cleSession;
    
    public TicketTGS(String client, String ip, LocalDate validty, Cle cleSession) {
        this.client = client;
        this.ip = ip;
        this.tv = validty;
        this.cleSession=cleSession;
    }
}
