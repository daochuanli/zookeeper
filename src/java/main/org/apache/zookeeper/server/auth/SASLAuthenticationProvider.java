package org.apache.zookeeper.server.auth;


import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.ServerCnxn;
import sun.util.LocaleServiceProviderPool;

public class SASLAuthenticationProvider implements AuthenticationProvider {
    public String getScheme() {
        return "sasl";
    }

    public KeeperException.Code
        handleAuthentication(ServerCnxn cnxn, byte[] authData)
    {
        // Should never call this: SASL authentication is negotiated at session initiation.
        // TODO: consider substituting current implementation of direct ClientCnxn manipulation with
        // a call to this method (SASLAuthenticationProvider:handleAuthentication()) at session initiation.
        return KeeperException.Code.AUTHFAILED;

    }

    public boolean matches(String id,String aclExpr) {
        return id.equals(aclExpr);
    }

    public boolean isAuthenticated() {
        // Should never be called.
        return false;
    }

    public boolean isValid(String id) {
        return true;
    }


}
