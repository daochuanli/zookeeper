package org.apache.zookeeper;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.callback.CallbackHandler;
import org.apache.log4j.Logger;

public class LoginThread extends Thread {

    Logger LOG = Logger.getLogger(LoginThread.class);

    private LoginContext loginContext;
    private String loginContextName;
    private CallbackHandler callbackHandler;
    
    public LoginThread(String loginContextName, CallbackHandler callbackHandler) {
            this.loginContextName = loginContextName;
            this.callbackHandler = callbackHandler;
            this.login();
            this.start();
    }

    public void run() {
        LOG.info("started.");
        while(true) {
            LOG.info("sleeping.");
            try {
                Thread.sleep(1 * 60 * 1000); // 10 minutes.
            }
            catch (InterruptedException e) {
                LOG.error("caught InterruptedException while sleeping. Waking and attempting credential renewal.");
            }
            login();
        }
    }

    public void login() {
        synchronized(this) {
            try {
                if (this.loginContext != null) {
                    this.loginContext.logout();
                }
                this.loginContext = new LoginContext(loginContextName,callbackHandler);
                this.loginContext.login();
                LOG.info("successfully logged in.");
            }
            catch (LoginException e) {
                LOG.error("Error while trying to do subject authentication using '"+this.loginContextName+"' section of " + System.getProperty("java.security.auth.login.config") + ":" + e);
            }
        }
    }
    
    public LoginContext getLogin() {
        synchronized(this) {
            return this.loginContext;
        }
    }
    
}

