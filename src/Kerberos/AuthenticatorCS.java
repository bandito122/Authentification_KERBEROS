package Kerberos;

import JavaLibrary.Crypto.HMAC.HMAC;
import java.io.Serializable;
import java.time.LocalDate;

/*
 * @author Julien
 */
public class AuthenticatorCS implements Serializable {
    public String client;
    public HMAC hmac;
    public LocalDate tv; //time-value

    public AuthenticatorCS(String client, LocalDate hcourant, HMAC hmac) {
        this.client = client;
        this.tv = hcourant;
        this.hmac = hmac;
    }
}
