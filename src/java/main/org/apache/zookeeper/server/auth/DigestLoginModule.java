package org.apache.zookeeper.server.auth;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;
import java.security.Principal;
import java.util.HashMap;
import java.util.Iterator;
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
        if (options.containsKey("username")) {
            // client.
            this.subject = subject;
            this.callbackHandler = callbackHandler;
            this.options = options;
            this.sharedState = sharedState;
            String username = (String)options.get("username");
            this.subject.getPublicCredentials().add((Object)username);
            String password = (String)options.get("password");
            this.subject.getPrivateCredentials().add((Object)password);
        }
        else {
            //server: save options: they are user->password pairs (except e.g. "debug").
            this.options = options;
            this.subject = subject;
            Map<String,String> userPassPairs = new HashMap<String,String>();

            Iterator it = options.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry pair = (Map.Entry)it.next();

                String key = (String)pair.getKey();
                if (key.substring(0,5).equals("user_")) {
                    String userName = key.substring(5);
                    userPassPairs.put(userName,(String)pair.getValue());
                }
            }
            this.subject.getPrivateCredentials().add((Object)userPassPairs);
        }

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


