/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper;

/** 
 * This class is responsible for refreshing Kerberos credentials for
 * logins for both Zookeeper client and server.
 * See ServerCnxnFactory.java:startLoginThread() for server-side usage
 * and Zookeeper.java:startLoginThread() for client-side usage.
 */

import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.callback.CallbackHandler;

import org.apache.log4j.Logger;
import sun.security.krb5.PrincipalName;

import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.Subject;
import java.io.IOException;
import java.util.Date;
import java.util.Set;

public class Login {

    Logger LOG = Logger.getLogger(Login.class);

    private LoginContext loginContext;
    private String loginContextName;
    public CallbackHandler callbackHandler;

    public boolean validCredentials = false;

    // LoginThread will sleep until 80% of time from last refresh to
    // ticket's expiry has been reached, at which time it will wake
    // and try to renew the ticket.
    private static final float TICKET_RENEW_WINDOW = 0.80f;

    // Regardless of TICKET_RENEW_WINDOW setting above and the ticket expiry time,
    // thread will not sleep between refresh attempts any less than 1 minute (60*1000 milliseconds = 1 minute).
    // Change the '1' to e.g. 5, to change this to 5 minutes.
    private static final long MIN_TIME_BEFORE_RELOGIN = 1 * 60 * 1000L;

    private long lastLogin;
    private Subject subject = null;
    private boolean isKrbTkt = false;
    private Thread t = null;
    /**
     * LoginThread constructor. The constructor starts the thread used
     * to periodically re-login to the Kerberos Ticket Granting Server.
     * @param loginContextName
     *               name of section in JAAS file that will be use to login.
     *               Passed as first param to javax.security.auth.login.LoginContext().
     *
     * @param callbackHandler
     *               Passed as second param to javax.security.auth.login.LoginContext().
     */
    public Login(final String loginContextName, CallbackHandler callbackHandler) {
        this.loginContextName = loginContextName;
        this.callbackHandler = callbackHandler;

        try {
            this.login();
            validCredentials = true;
            // determine Kerberos-related info, if any.
            this.subject = loginContext.getSubject();
            this.isKrbTkt = !subject.getPrivateCredentials(KerberosTicket.class).isEmpty();

            if (this.isKrbTkt == true) {
                t = new Thread(new Runnable() {
                    public void run() {
                        LOG.info("TGT refresh thread started.");
                        // TODO : make this a configurable option or search
                        // a set of likely paths {/usr/bin/, /usr/krb5/bin, ...}
                        String cmd = "/usr/bin/kinit";
                        KerberosTicket tgt = getTGT();
                        if (tgt == null) {
                            return;
                        }
                        while (true) {
                            try {
                                long now = System.currentTimeMillis();
                                long nextRefresh = getRefreshTime(tgt);
                                if (nextRefresh < (now + MIN_TIME_BEFORE_RELOGIN)) {
                                    Date until = new Date(nextRefresh);
                                    Date newuntil = new Date(now + MIN_TIME_BEFORE_RELOGIN);
                                    LOG.warn("TGT refresh thread time adjusted from : " + until + " to : " + newuntil + " since "
                                      + until + " is less than "
                                      + MIN_TIME_BEFORE_RELOGIN / 1000 + " seconds from now.");
                                }
                                nextRefresh = Math.max(nextRefresh, now + MIN_TIME_BEFORE_RELOGIN);
                                if (now < nextRefresh) {
                                    Date until = new Date(nextRefresh);
                                    LOG.info("TGT refresh thread sleeping until: " + until.toString());
                                    Thread.sleep(nextRefresh - now);
                                }

                                Date nextRefreshDate = new Date(nextRefresh);
                                try {
                                    Shell.execCommand(cmd,"-R");
                                    LOG.debug("renewed ticket");
                                    reloginFromTicketCache();
                                    tgt = getTGT();
                                }
                                catch (Shell.ExitCodeException e) {
                                    LOG.error("Could not renew TGT due to problem running shell command: '" + cmd + " -R'" + "; exception was:" + e + ". Will try shell command again at: " + nextRefreshDate);
                                }

                                if (tgt == null) {
                                    LOG.warn("No TGT after renewal. Aborting renew thread for " + getPrincipalName());
                                }

                            }
                            catch (InterruptedException ie) {
                                LOG.warn("TGT renewal thread has been interrupted and will exit.");
                                break;
                            }
                            catch (IOException ie) {
                                LOG.warn("Exception encountered while running the" +
                                  " renewal command. Aborting renew thread", ie);
                                return;
                            }
                        }
                    }
                });
                t.start();
            }
            else {
                LOG.error("Authentication was not via Ticket Cache: will not start a TGT renewal thread.");
            }
        }
        catch (LoginException e) {
            LOG.error("Error while trying to do subject authentication using '"
                    + this.loginContextName+"' section of "
                    + System.getProperty("java.security.auth.login.config")
                    + ":" + e + ".");
            validCredentials = false;
        }
    }

    public void login() throws LoginException {
        synchronized(this) {
            if (this.loginContext != null) {
                this.loginContext.logout();
            }
            this.loginContext = new LoginContext(loginContextName,callbackHandler);
            this.loginContext.login();
            LOG.info("successfully logged in.");
            validCredentials = true;
            setLastLogin(System.currentTimeMillis());
        }
    }
    
    public LoginContext getLogin() {
        synchronized(this) {
            return this.loginContext;
        }
    }

    // c.f. org.apache.hadoop.security.UserGroupInformation.
    private long getRefreshTime(KerberosTicket tgt) {
        long start = tgt.getStartTime().getTime();
        long end = tgt.getEndTime().getTime();
        LOG.info("TGT valid starting at: " + tgt.getStartTime().toString());
        LOG.info("TGT expires: " + tgt.getEndTime().toString());
        return start + (long) ((end - start) * TICKET_RENEW_WINDOW);
    }

    private synchronized KerberosTicket getTGT() {
        Set<KerberosTicket> tickets = subject.getPrivateCredentials(KerberosTicket.class);
        for(KerberosTicket ticket: tickets) {
            KerberosPrincipal server = ticket.getServer();
            if (server.getName().equals("krbtgt/" + server.getRealm() + "@" + server.getRealm())) {
                LOG.debug("Found tgt " + ticket + ".");
                return ticket;
            }
        }
        return null;
    }

    // TODO : refactor this with login() to maximize code-sharing.
    public synchronized void reloginFromTicketCache()
        throws IOException {
        if (!isKrbTkt) {
            return;
        }
        LoginContext login = getLogin();
        if (login == null) {
            throw new IOException("login must be done first");
        }
        if (!hasSufficientTimeElapsed()) {
            return;
        }
        final String principalName = getPrincipalName();
        try {
            LOG.info("Initiating logout for " + principalName);
            //clear up the Kerberos state. But the tokens are not cleared! As per
            //the Java kerberos login module code, only the kerberos credentials
            //are cleared.
            login.logout();
            //login and also update the subject field of this instance to
            //have the new credentials (pass it to the LoginContext constructor)
            if (loginContextName == null) {
                throw new LoginException("loginContext name (JAAS file section header) was null. " +
                  "Please check your java.security.login.auth.config setting.");
            }
            if (subject == null) {
                throw new LoginException("login subject was null.");
            }
            login =new LoginContext(loginContextName,subject);
            LOG.info("Initiating re-login for " + principalName);
            login.login();
        } catch (LoginException le) {
            throw new IOException("Login failure for " + principalName);
        }
    }

    private String getPrincipalName() {
        try {
            return (getLogin().getSubject().getPrincipals(KerberosPrincipal.class).toArray())[0].toString();
        }
        catch (NullPointerException e) {
            LOG.warn("could not display principal name because login was null or login's subject was null: returning '(no principal found)'.");
        }
        catch (ArrayIndexOutOfBoundsException e) {
            LOG.warn("could not display principal name because login's subject had no principals: returning '(no principal found)'.");
        }
        return "(no principal found)";
    }

    private boolean hasSufficientTimeElapsed() {
        long now = System.currentTimeMillis();
        if (now - getLastLogin() < MIN_TIME_BEFORE_RELOGIN) {
            // in Hadoop code this was LOG.warn(), which causes a lot of false alarms in production.
            // Figure out how to better diagnose why we get here and reduce
            // unnecessary calls to hasSufficientTimeElapsed().
            LOG.info("Not attempting to re-login since the last re-login was " +
              "attempted less than " + (MIN_TIME_BEFORE_RELOGIN/1000) + " seconds "+ "before.");
            return false;
        }
        setLastLogin(now);
        return true;
    }

    private void setLastLogin(long loginTime) {
        lastLogin = loginTime;
    }

    private long getLastLogin() {
        return lastLogin;
    }

    public void shutdown() {
        if ((t != null) && (t.isAlive())) {
            t.interrupt();
            try {
                t.join();
            }
            catch (InterruptedException e) {
                LOG.error("error while waiting for Login thread to shutdown: " + e);
            }
        }
    }

}

