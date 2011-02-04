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

package org.apache.zookeeper.server;

import java.io.File;
import java.io.IOException;

import javax.management.JMException;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.log4j.Logger;
import org.apache.zookeeper.jmx.ManagedUtil;
import org.apache.zookeeper.server.persistence.FileTxnSnapLog;
import org.apache.zookeeper.server.quorum.QuorumPeerConfig.ConfigException;

/**
 * This class starts and runs a standalone ZooKeeperServer.
 */
public class ZooKeeperServerMain {
    private static final Logger LOG =
        Logger.getLogger(ZooKeeperServerMain.class);

    private static final String USAGE =
        "Usage: ZooKeeperServerMain configfile | port datadir [ticktime] [maxcnxns]";

    private ServerCnxnFactory cnxnFactory;

    /*
     * Start up the ZooKeeper server.
     *
     * @param args the configfile or the port datadir [ticktime]
     */
    public static void main(String[] args) {
        ZooKeeperServerMain main = new ZooKeeperServerMain();
        try {
            main.initializeAndRun(args);
        } catch (IllegalArgumentException e) {
            LOG.fatal("Invalid arguments, exiting abnormally", e);
            LOG.info(USAGE);
            System.err.println(USAGE);
            System.exit(2);
        } catch (ConfigException e) {
            LOG.fatal("Invalid config, exiting abnormally", e);
            System.err.println("Invalid config, exiting abnormally");
            System.exit(2);
        } catch (Exception e) {
            LOG.fatal("Unexpected exception, exiting abnormally", e);
            System.exit(1);
        }
        LOG.info("Exiting normally");
        System.exit(0);
    }

    protected void initializeAndRun(String[] args)
        throws ConfigException, IOException
    {
        try {
            ManagedUtil.registerLog4jMBeans();
        } catch (JMException e) {
            LOG.warn("Unable to register log4j JMX control", e);
        }

        ServerConfig config = new ServerConfig();
        if (args.length == 1) {
            config.parse(args[0]);
        } else {
            config.parse(args);
        }

        runFromConfig(config);
    }

    /**
     * Run from a ServerConfig.
     * @param config ServerConfig to use.
     * @throws IOException
     */
    public void runFromConfig(ServerConfig config) throws IOException {
        LOG.info("Starting server");
        try {
            // Note that this thread isn't going to be doing anything else,
            // so rather than spawning another thread, we will just call
            // run() in this thread.
            // create a file logger url from the command line args
            ZooKeeperServer zkServer = new ZooKeeperServer();

            FileTxnSnapLog ftxn = new FileTxnSnapLog(new
                   File(config.dataLogDir), new File(config.dataDir));
            zkServer.setTxnLogFactory(ftxn);
            zkServer.setTickTime(config.tickTime);
            zkServer.setMinSessionTimeout(config.minSessionTimeout);
            zkServer.setMaxSessionTimeout(config.maxSessionTimeout);
            cnxnFactory = ServerCnxnFactory.createFactory();

            Subject subject = setupSubject(config.getJaasConf(),config.getAuthMech());
            cnxnFactory.configure(config.getClientPortAddress(),
                    config.getMaxClientCnxns(),
                    subject);
            cnxnFactory.startup(zkServer);
            cnxnFactory.join();
            if (zkServer.isRunning()) {
                zkServer.shutdown();
            }
        } catch (InterruptedException e) {
            // warn, but generally this is ok
            LOG.warn("Server interrupted", e);
        }
    }

    /**
     * Shutdown the serving instance
     */
    protected void shutdown() {
        cnxnFactory.shutdown();
    }

    protected Subject setupSubject(String jaasConf, String authMech) {
        // This initializes zkServerSubject.
        // Should be called only once, at server startup time.
        System.setProperty("javax.security.sasl.level","FINEST");

        // TODO: Figure out what this does and if it's needed.
        System.setProperty("handlers", "java.util.logging.ConsoleHandler");

        if (System.getProperty("java.security.auth.login.config") != null) {
            LOG.info("Using JAAS configuration file: " + System.getProperty("java.security.auth.login.config"));
        }
        else {
            System.setProperty("java.security.auth.login.config",jaasConf);
        }

        Subject zkServerSubject;
        if (authMech.equals("DIGEST-MD5")) {
            LoginContext loginCtx = null;
            final String SERVICE_SECTION_OF_JAAS_CONF_FILE = "Server";
            try {
                loginCtx = new LoginContext(SERVICE_SECTION_OF_JAAS_CONF_FILE);
                // DigestLoginModule loads passwords from Server section of the JAAS conf file.
                loginCtx.login();
                zkServerSubject = loginCtx.getSubject();
                LOG.info("Zookeeper Quorum member successfully SASL-authenticated using " + authMech + " mechanism.");
                return zkServerSubject;
            }
            catch (LoginException e) {
                LOG.error("Zookeeper Quorum member failed to SASL-authenticate using " + authMech + " mechanism: " + e);
                e.printStackTrace();
                System.exit(-1);
            }

            return null;
        }

        // (authmech != DIGEST-MD5) => GSSAPI
        //
        // If using Kerberos, the file given in JAAS config file must have :
        //
        // $SERVICE_SECTION_OF_JAAS_CONF_FILE {
        //   com.sun.security.auth.module.Krb5LoginModule required
        //   useKeyTab=true
        //   keyTab="$KEY_TAB_FILE_NAME"
        //   doNotPrompt=true
        //   useTicketCache=false
        //   storeKey=true
        //   principal="$SERVICE_NAME/$HOST_NAME";
        // };

        try {
            // 1. Service Login.
            LoginContext loginCtx = null;
            final String SERVICE_SECTION_OF_JAAS_CONF_FILE = "Server";
            loginCtx = new LoginContext(SERVICE_SECTION_OF_JAAS_CONF_FILE);
            loginCtx.login();
            zkServerSubject = loginCtx.getSubject();
            LOG.info("Zookeeper Quorum member successfully SASL-authenticated.");
            return zkServerSubject;
        }
        catch (LoginException e) {
            LOG.error("Zookeeper Quorum member failed to SASL-authenticate: " + e);
            e.printStackTrace();
            System.exit(-1);
        }
        return null;
    }



}

