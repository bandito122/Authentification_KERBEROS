package Network;

import GestionSocket.ISocket;
import RequestResponse.ConsoleServeur;
import RequestResponse.IRequest;
import java.io.Serializable;

/*
 * @author Julien
 * Classe représentant une requête du client au serveur et vice-versa. 
 */
public class Request implements IRequest, Serializable {
    private int type;
    Object chargeUtile;

    public Request(int type) {
        this.type=type;
        chargeUtile=""; //object pas serializable, pas défaut donc, c'est un String
    }
    
    @Override
    public boolean executeRequest(ISocket Socket, ConsoleServeur guiApplicaiton) {
        // ré-implémenter?
        return false;
    }

    @Override
    public int getType() {
        return type;
    }

    @Override
    public void setType(int type) {
        this.type=type;
    }

    @Override
    public Object getChargeUtile() {
        return this.chargeUtile;
    }

    @Override
    public void setChargeUtile(Object obj) {
        this.chargeUtile=obj;
    }

}
