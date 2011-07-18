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

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.callback.CallbackHandler;

import com.sun.org.apache.bcel.internal.generic.NEW;
import org.apache.log4j.Logger;
import sun.awt.shell.ShellFolder;
import sun.security.krb5.internal.crypto.NullEType;

import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.Subject;
import java.io.IOException;
import java.nio.channels.NonWritableChannelException;
import java.util.Set;

public class LoginThread {

    Logger LOG = Logger.getLogger(LoginThread.class);

    private LoginContext loginContext;
    private String loginContextName;
    public CallbackHandler callbackHandler;
    private int sleepInterval;

    public boolean validCredentials = false;

    private static final float TICKET_RENEW_WINDOW = 0.80f;

    private Subject subject = null;
    private boolean isKeytab = false;
    private boolean isKrbTkt = false;

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
    public LoginThread(String loginContextName, CallbackHandler callbackHandler, Integer sleepInterval) {
        this.loginContextName = loginContextName;
        this.callbackHandler = callbackHandler;
        this.sleepInterval = sleepInterval;

        try {
            this.login();
            validCredentials = true;
            // determine Kerberos-related info, if any.
            this.subject = loginContext.getSubject();
            this.isKeytab = !subject.getPrivateCredentials(KerberosKey.class).isEmpty();
            this.isKrbTkt = !subject.getPrivateCredentials(KerberosTicket.class).isEmpty();

            if (isKrbTkt) {
                Thread t = new Thread(new Runnable() {
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
                                    Thread.sleep(nextRefresh - now);
                                }
                                Shell.execCommand(cmd,"-R");
                                LOG.debug("renewed ticket");
                                reloginFromTicketCache();
                                tgt = getTGT();
                                if (tgt == null) {
                                    LOG.warn("No TGT after renewal. Aborting renew thread for " + getUserName());
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
            }
        }
        catch (LoginException e) {
            LOG.error("Error while trying to do subject authentication using '"
                    + this.loginContextName+"' section of "
                    + System.getProperty("java.security.auth.login.config")
                    + ":" + e + ". Interrupting loginThread now; will exit.");
	    LOG.error("Zookeeper client will connect without SASL authentication, if permitted by Zookeeper server.");
            validCredentials = false;
            this.interrupt();
        }
    }

    public void run() {
        if (this.sleepInterval < 1000) {
            LOG.warn("Sleep interval: " + this.sleepInterval + " is too small: not sleeping; simply exiting run().");
            return;
        }
        LOG.info("Login Refresh thread started. Will refresh login every " + this.sleepInterval + " milliseconds.");

        while(true) {
            LOG.info("sleeping.");
            try {
                // TODO: make this configurable: should run after 80% of time
                // until last ticket expiry.
                Thread.sleep(sleepInterval);
            }
            catch (InterruptedException e) {
                // A creator of a LoginThread object should call .interrupt() and .join() on its
                // LoginThread object prior to the creator's shutting down.
                LOG.error("caught InterruptedException while sleeping. Breaking out of endless loop.");
                break;
            }
            try {
                login();
            }
            catch (LoginException e) {
                LOG.error("Error while trying to do subject authentication using '"
                        + this.loginContextName+"' section of "
                        + System.getProperty("java.security.auth.login.config")
                        + ":" + e + ". Interrupting loginThread now; will exit.");
                validCredentials = false;
                break;
            }
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
                LOG.debug("Found tgt " + ticket ".");
                return ticket;
            }
        }
        return null;
    }


    
}

