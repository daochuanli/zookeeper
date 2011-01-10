package org.apache.zookeeper.server.auth;


import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.ServerCnxn;

public class SASLAuthenticationProvider implements AuthenticationProvider {
    public String getScheme() {
        return "sasl";
    }

    public KeeperException.Code
        handleAuthentication(ServerCnxn cnxn, byte[] authData)
    {
//        String id = cnxn.
        //  saslServer.getAuthorizationID();
        String id = new String("foo");
        cnxn.addAuthInfo(new Id(getScheme(), id));
        return KeeperException.Code.OK;
    }

    public boolean matches(String id,String aclExpr) {
        return false;
    }

    public boolean isAuthenticated() {
        return false;
    }

    public boolean isValid(String id) {
        if (id.equals("testclient:x")) {
            return true;
        }
        else {
            return false;
        }
    }


}
