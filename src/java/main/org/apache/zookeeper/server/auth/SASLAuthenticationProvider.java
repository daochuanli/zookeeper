package org.apache.zookeeper.server.auth;


import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.ServerCnxn;

import java.util.Map;

public class SASLAuthenticationProvider implements AuthenticationProvider {
    private Map<String,String> credentials;


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

    public void addCredentials(final String id, final String user, final String password) {
        if (id.equals("super")) { // only superuser can add new DIGEST-MD5 users or change users' passwords.
            this.credentials.put(user,password);
        }
    }


    public boolean matches(String id,String aclExpr) {
        return (id.equals("super") || id.equals(aclExpr));
    }

    public boolean isAuthenticated() {
        return true;
    }

    public boolean isValid(String id) {
        return true;
   }


}
