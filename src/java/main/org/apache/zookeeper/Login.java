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
 * See ZooKeeperSaslServer for server-side usage.
 * See ZooKeeperSaslClient for client-side usage.
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

public class Login {
    Logger LOG = Logger.getLogger(Login.class);
    public CallbackHandler callbackHandler;

    // LoginThread will sleep until 80% of time from last refresh to
    // ticket's expiry has been reached, at which time it will wake
    // and try to renew the ticket.
    private static final float TICKET_RENEW_WINDOW = 0.80f;

    // Regardless of TICKET_RENEW_WINDOW setting above and the ticket expiry time,
    // thread will not sleep between refresh attempts any less than 1 minute (60*1000 milliseconds = 1 minute).
    // Change the '1' to e.g. 5, to change this to 5 minutes.
    private static final long MIN_TIME_BEFORE_RELOGIN = 1 * 60 * 1000L;

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
    public Login(final String loginContextName, CallbackHandler callbackHandler)
      throws LoginException {
        this.callbackHandler = callbackHandler;
        final LoginContext loginContext = login(loginContextName);
        this.subject = loginContext.getSubject();
        this.isKrbTkt = !subject.getPrivateCredentials(KerberosTicket.class).isEmpty();

        if (this.isKrbTkt) {
            t = new Thread(new Runnable() {
                public void run() {
                    LOG.info("TGT refresh thread started.");
                    while (true) {  // renewal thread's main loop. if it exits from here, thread will exit.
                        KerberosTicket tgt = getTGT();
                        if (tgt == null) {
                            LOG.warn("No tgt found: ticket cache refresh thread will exit.");
                            return;
                        }
                        long now = System.currentTimeMillis();
                        long nextRefresh = getRefreshTime(tgt);
                        long expiry = tgt.getEndTime().getTime();
                        if ((nextRefresh < (now + MIN_TIME_BEFORE_RELOGIN)) &&
                          ((now + MIN_TIME_BEFORE_RELOGIN) < expiry)) {
                            Date until = new Date(nextRefresh);
                            Date newuntil = new Date(now + MIN_TIME_BEFORE_RELOGIN);
                            LOG.warn("TGT refresh thread time adjusted from : " + until + " to : " + newuntil + " since "
                              + "the former is sooner than the minimum refresh interval ("
                              + MIN_TIME_BEFORE_RELOGIN / 1000 + " seconds) from now.");
                        }
                        nextRefresh = Math.min(Math.max(nextRefresh, now + MIN_TIME_BEFORE_RELOGIN),expiry);
                        Date nextRefreshDate = new Date(nextRefresh);
                        if (now < nextRefresh) {
                            Date until = new Date(nextRefresh);
                            LOG.info("TGT refresh thread sleeping until: " + until.toString());
                            try {
                                Thread.sleep(nextRefresh - now);
                            }
                            catch (InterruptedException ie) {
                                LOG.warn("TGT renewal thread has been interrupted and will exit.");
                                break;
                            }
                        }
                        else {
                            LOG.warn("nextRefresh:" + nextRefreshDate + " is in the past.");
                        }
                        // TODO : make this a configurable option or search
                        // a set of likely paths {/usr/bin/, /usr/krb5/bin, ...}
                        String cmd = "/usr/bin/kinit";
                        try {
                            Shell.execCommand(cmd,"-R");
                        }
                        catch (Shell.ExitCodeException e) {
                            LOG.error("Could not renew TGT due to problem running shell command: '" + cmd
                              + " -R'" + "; exception was:" + e + ". Will try shell command again at: "
                              + nextRefreshDate);
                        }
                        catch (IOException e) {
                            LOG.error("Could not renew TGT due to problem running shell command: '" + cmd
                              + " -R'" + "; exception was:" + e + ". Will try shell command again at: "
                              + nextRefreshDate);
                        }
                        try {
                            reloginFromTicketCache(loginContextName, loginContext);
                            LOG.debug("renewed TGT successfully.");
                        }
                        catch (LoginException e) {
                            LOG.error("Could not renew TGT : " + e + "."
                              + "Will try again at: "
                              + nextRefreshDate);
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

    private synchronized LoginContext login(final String loginContextName) throws LoginException {
        if (loginContextName == null) {
            throw new LoginException("loginContext name (JAAS file section header) was null. " +
              "Please check your java.security.login.auth.config setting.");
        }
        LoginContext loginContext = new LoginContext(loginContextName,callbackHandler);
        loginContext.login();
        LOG.info("successfully logged in.");
        return loginContext;
    }

    public Subject getSubject() {
        return subject;
    }

    // c.f. org.apache.hadoop.security.UserGroupInformation.
    private long getRefreshTime(KerberosTicket tgt) {
        long start = tgt.getStartTime().getTime();
        long expires = tgt.getEndTime().getTime();
        LOG.info("TGT valid starting at: " + tgt.getStartTime().toString());
        LOG.info("TGT expires: " + tgt.getEndTime().toString());
        long proposedRefresh = start + (long) ((expires - start) * TICKET_RENEW_WINDOW);
        if (proposedRefresh > expires) {
            // proposedRefresh is too far in the future: it's after ticket expires: simply return now.
            return System.currentTimeMillis();
        }
        else {
            return proposedRefresh;
        }
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
    public synchronized void reloginFromTicketCache(final String loginContextName, LoginContext loginContext)
        throws LoginException {
        if (!isKrbTkt) {
            return;
        }
        if (loginContext == null) {
            throw new LoginException("login must be done first");
        }
        final String principalName = getPrincipalName();
        try {
            LOG.info("Initiating logout for " + principalName);
            //clear up the Kerberos state. But the tokens are not cleared! As per
            //the Java kerberos login module code, only the kerberos credentials
            //are cleared.
            loginContext.logout();
            //login and also update the subject field of this instance to
            //have the new credentials (pass it to the LoginContext constructor)
            if (loginContextName == null) {
                throw new LoginException("loginContext name (JAAS file section header) was null. " +
                  "Please check your java.security.login.auth.config setting.");
            }
            if (subject == null) {
                throw new LoginException("login subject was null.");
            }
            LOG.info("Initiating re-login for " + principalName);
            loginContext.login();
        } catch (LoginException le) {
            throw new LoginException("Login failure for " + principalName);
        }
    }

    private String getPrincipalName() {
        try {
            return getSubject().getPrincipals(KerberosPrincipal.class).toArray()[0].toString();
        }
        catch (NullPointerException e) {
            LOG.warn("could not display principal name because login was null or login's subject was null: returning '(no principal found)'.");
        }
        catch (ArrayIndexOutOfBoundsException e) {
            LOG.warn("could not display principal name because login's subject had no principals: returning '(no principal found)'.");
        }
        return "(no principal found)";
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

