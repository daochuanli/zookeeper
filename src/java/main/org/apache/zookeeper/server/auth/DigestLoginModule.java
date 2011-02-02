package org.apache.zookeeper.server.auth;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;
import java.util.Map;

public class DigestLoginModule implements LoginModule {
    private CallbackHandler callbackHandler;
    private Subject subject;
    private Map<String,?> options;
    private Map<String,?> sharedState;

    public boolean abort() {
        return false;
    }

    public boolean commit() {
        return true;
    }

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String,?> sharedState, Map<String,?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.options = options;
        this.sharedState = sharedState;
        String username = (String)options.get("username");
        this.subject.getPublicCredentials().add((Object)username);
        String password = (String)options.get("password");
        this.subject.getPrivateCredentials().add((Object)password);

        return;
    }

    public boolean logout() {
        return true;
    }

    public boolean login() {
        // Unlike with Krb5LoginModule, we don't do any actual login or credential passing here: authentication to Zookeeper
        // is done later, through the SASLClient object.
        return true;
    }

}


