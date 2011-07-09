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
 * See o.a.z.client.ZooKeeperSaslClient.java:startLoginThread() for client-side usage
 * and o.a.z.server.ZookeeperSaslServer.java:startLoginThread() for server-side usage.
 */

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.callback.CallbackHandler;
import org.apache.log4j.Logger;

public class LoginThread extends Thread {

    Logger LOG = Logger.getLogger(LoginThread.class);

    private LoginContext loginContext;
    private String loginContextName;
    public CallbackHandler callbackHandler;
    private int sleepInterval;

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
        this.setDaemon(true);

        this.login();
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
                   Thread.sleep(sleepInterval);
            }
            catch (InterruptedException e) {
                // A creator object O of a LoginThread object should call .interrupt() and .join() on its
                // LoginThread object prior to O's shutting down: see ZooKeeperSaslClient.close() and 
                // ZooKeeperSaslServer.shutdown().
                LOG.error("caught InterruptedException while sleeping. Breaking out of endless loop.");
                break;
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
                LOG.info("successfully logged in using login context '"+loginContextName+"'.");
            }
            catch (LoginException e) {
                LOG.error("Error while trying to do subject authentication using '"+this.loginContextName+"' section of java.security.auth.login.config file: " + System.getProperty("java.security.auth.login.config") + ":" + e);
            }
        }
    }
    
    public LoginContext getLogin() {
        synchronized(this) {
            return this.loginContext;
        }
    }
    
}

