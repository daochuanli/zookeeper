package org.apache.zookeeper.server.auth;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;
import java.util.Map;

public class DigestLoginModule implements LoginModule {
    public boolean abort() {
        return false;
    }

    public boolean commit() {
        return true;
    }

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String,?> sharedState, Map<String,?> options) {
        return;
    }

    public boolean logout() {
        return true;
    }

    public boolean login() {
        return true;
    }

}