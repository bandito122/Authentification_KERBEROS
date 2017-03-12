package Kerberos;


import Utils.ByteUtils;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/*
 * @author Julien
 */
public class TicketTGS implements Serializable {
    //{nom du client, son ip, validité du ticket, 
    //cle de session} chiffré avec la clé du serveur
    String client, ip;
    LocalDate validty;
    
    public TicketTGS(String client, String ip, LocalDate validty) {
        this.client = client;
        this.ip = ip;
        this.validty = validty;
    }
    
    public byte[] getCipherTicket(String transformation, SecretKey sk) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, IOException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher=Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, sk);
        return cipher.doFinal(ByteUtils.toByteArray(this));
    }
}