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
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.Subject;
import java.io.IOException;
import java.util.Date;
import java.util.Set;

public class LoginThread {

    Logger LOG = Logger.getLogger(LoginThread.class);

    private LoginContext loginContext;
    private String loginContextName;
    public CallbackHandler callbackHandler;

    public boolean validCredentials = false;

    private static final float TICKET_RENEW_WINDOW = 0.80f;
    private static final long MIN_TIME_BEFORE_RELOGIN = 10 * 60 * 1000L;

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
     * @param sleepInterval
     *               How long to sleep between each LoginContext renewal.
     */
    public LoginThread(final String loginContextName, CallbackHandler callbackHandler) {
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
                        String cmd = "/usr/bin/kinit";
                        KerberosTicket tgt = getTGT();
                        if (tgt == null) {
                            return;
                        }
                        long nextRefresh = getRefreshTime(tgt);
                        while (true) {
                            try {
                                long now = System.currentTimeMillis();
                                LOG.debug("Current time is " + now);
                                LOG.debug("Next refresh is " + nextRefresh);
                                if (now < nextRefresh) {
                                    Date until = new Date(nextRefresh);
                                    LOG.info("TGT refresh thread for " + getPrincipalName() +  " sleeping until : " + until.toString());
                                    Thread.sleep(nextRefresh - now);
                                }
                                Shell.execCommand(cmd,"-R");
                                LOG.debug("renewed ticket");
                                reloginFromTicketCache();
                                tgt = getTGT();
                                if (tgt == null) {
                                    LOG.warn("No TGT after renewal. Aborting renew thread for " + getPrincipalName());
                                }
                                nextRefresh = Math.max(getRefreshTime(tgt), now + MIN_TIME_BEFORE_RELOGIN);
                            }
                            catch (InterruptedException ie) {
                                LOG.warn("Terminating renewal thread");
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
        }
        catch (LoginException e) {
            LOG.error("Error while trying to do subject authentication using '"
                    + this.loginContextName+"' section of "
                    + System.getProperty("java.security.auth.login.config")
                    + ":" + e + ". Interrupting loginThread now; will exit.");
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

    // c.f. o.a.hadoop.security.UserGroupInformation.
    private long getRefreshTime(KerberosTicket tgt) {
        long start = tgt.getStartTime().getTime();
        long end = tgt.getEndTime().getTime();
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

    public synchronized void reloginFromTicketCache()
        throws IOException {
        if (!isKrbTkt) {
            return;
        }
        LoginContext login = getLogin();
        if (login == null) {
            throw new IOException("login must be done first");
        }
        if (!hasSufficentTimeElapsed()) {
            return;
        }
        try {
            LOG.info("Initiating logout for " + getPrincipalName());
            //clear up the Kerberos state. But the tokens are not cleared! As per
            //the Java kerberos login module code, only the kerberos credentials
            //are cleared.
            login.logout();
            //login and also update the subject field of this instance to
            //have the new credentials (pass it to the LoginContext constructor)
            login =
              new LoginContext(loginContextName,subject);
            LOG.info("Initiating re-login for " + this.getPrincipalName());
            login.login();
        } catch (LoginException le) {
            throw new IOException("Login failure for " + getPrincipalName());
        }
    }

    private String getPrincipalName() {
        try {
            return (getLogin().getSubject().getPrincipals(KerberosPrincipal.class).toArray())[0].toString();
        }
        catch (NullPointerException e) {
            LOG.warn("could not display principal name because login was null, login's subject was null, or login's subject had no principals: returning '(no principal found)'.");
        }
        return "(no principal found)";
    }

    private boolean hasSufficentTimeElapsed() {
        long now = System.currentTimeMillis();
        if (now - getLastLogin() < MIN_TIME_BEFORE_RELOGIN) {
            LOG.warn("Not attempting to re-login since the last re-login was " +
              "attempted less than " + (MIN_TIME_BEFORE_RELOGIN/1000) + " seconds"+ "before.");
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
                LOG.error("error while waiting for loginThread to shutdown: " + e);
            }
        }
    }

}

