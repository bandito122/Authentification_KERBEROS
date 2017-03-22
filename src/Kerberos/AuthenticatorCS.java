package Kerberos;

import JavaLibrary.Utils.ByteUtils;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/*
 * @author Julien
 */
public class AuthenticatorCS implements Serializable {
    public String client,checksum;
    public LocalDateTime hcourant;

    public AuthenticatorCS(String client, LocalDateTime hcourant, String checksum) {
        this.client = client;
        this.hcourant = hcourant;
        this.checksum = checksum;
    }
}
