/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Kerberos;

import JavaLibrary.Crypto.Cle;
import java.io.Serializable;
import java.time.LocalDate;

/**
 *
 * @author bobmastrolilli
 */
public class TicketTCS implements Serializable 
{
    //{nom du client, son ip, validité du ticket, 
    //cle de session} chiffré avec la clé du serveur
    public String client, ip;
    public LocalDate tv;
    public Cle cleSession;
    
    public TicketTCS(String client, String ip, LocalDate validty, Cle cleSession) 
    {
        this.client = client;
        this.ip = ip;
        this.tv = validty;
        this.cleSession=cleSession;
    }
}