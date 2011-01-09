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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;

import javax.management.JMException;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.apache.log4j.Logger;
import org.apache.zookeeper.jmx.MBeanRegistry;

public abstract class ServerCnxnFactory {
    
    public static final String ZOOKEEPER_SERVER_CNXN_FACTORY = "zookeeper.serverCnxnFactory";

    public interface PacketProcessor {
        public void processPacket(ByteBuffer packet, ServerCnxn src);
    }

    Logger LOG = Logger.getLogger(ServerCnxnFactory.class);

    /**
     * The buffer will cause the connection to be close when we do a send.
     */
    static final ByteBuffer closeConn = ByteBuffer.allocate(0);

    public abstract int getLocalPort();
    
    public abstract Iterable<ServerCnxn> getConnections();

    public abstract void closeSession(long sessionId);

    public abstract void configure(InetSocketAddress addr,
            int maxClientCnxns) throws IOException;

    /** Maximum number of connections allowed from particular host (ip) */
    public abstract int getMaxClientCnxnsPerHost();

    /** Maximum number of connections allowed from particular host (ip) */
    public abstract void setMaxClientCnxnsPerHost(int max);

    public abstract void startup(ZooKeeperServer zkServer)
        throws IOException, InterruptedException;

    public abstract void join() throws InterruptedException;

    public abstract void shutdown();

    public abstract void start();

    protected ZooKeeperServer zkServer;
    final public void setZooKeeperServer(ZooKeeperServer zk) {
        this.zkServer = zk;
        if (zk != null) {
            zk.setServerCnxnFactory(this);
        }
    }

    public abstract void closeAll();
    
    static public ServerCnxnFactory createFactory() throws IOException {
        String serverCnxnFactoryName =
            System.getProperty(ZOOKEEPER_SERVER_CNXN_FACTORY);
        if (serverCnxnFactoryName == null) {
            serverCnxnFactoryName = NIOServerCnxnFactory.class.getName();
        }
        try {
            return (ServerCnxnFactory) Class.forName(serverCnxnFactoryName)
                                                .newInstance();
        } catch (Exception e) {
            IOException ioe = new IOException("Couldn't instantiate "
                    + serverCnxnFactoryName);
            ioe.initCause(e);
            throw ioe;
        }
    }
    
    static public ServerCnxnFactory createFactory(int clientPort,
            int maxClientCnxns) throws IOException
    {
        return createFactory(new InetSocketAddress(clientPort), maxClientCnxns);
    }

    static public ServerCnxnFactory createFactory(InetSocketAddress addr,
            int maxClientCnxns) throws IOException
    {
        ServerCnxnFactory factory = createFactory();
        factory.configure(addr, maxClientCnxns);
        return factory;
    }

    public abstract InetSocketAddress getLocalAddress();

    private HashMap<ServerCnxn, ConnectionBean> connectionBeans = new HashMap<ServerCnxn, ConnectionBean>();
    public void unregisterConnection(ServerCnxn serverCnxn) {
        ConnectionBean jmxConnectionBean = connectionBeans.remove(serverCnxn);
        if (jmxConnectionBean != null){
            MBeanRegistry.getInstance().unregister(jmxConnectionBean);
        }
    }
    
    public void registerConnection(ServerCnxn serverCnxn) {
        if (zkServer != null) {
            ConnectionBean jmxConnectionBean = new ConnectionBean(serverCnxn, zkServer);
            try {
                MBeanRegistry.getInstance().register(jmxConnectionBean, zkServer.jmxServerBean);
                connectionBeans.put(serverCnxn, jmxConnectionBean);
            } catch (JMException e) {
                LOG.warn("Could not register connection", e);
            }
        }

    }

    private Subject zkServerSubject;

    public Subject getSubject() {
        return zkServerSubject;
    }

    protected void setupSubject() {
        // This initializes zkServerSubject.
        // Should be called only once, at server startup time.
        System.setProperty("javax.security.sasl.level","FINEST");
        System.setProperty("handlers", "java.util.logging.ConsoleHandler");

        // SASL/Kerberos-related constants:
        // TODO: these are hardwired and redundant (see ZooKeeperMain.java and ClientCnxn.java); use zoo.cfg instead.
        final String JAAS_CONF_FILE_NAME = "jaas.conf";
        final String HOST_NAME = "ekoontz";
        final String SERVICE_PRINCIPAL_NAME = "testserver";
        final String SERVICE_SECTION_OF_JAAS_CONF_FILE = "Server";
        final String KEY_TAB_FILE_NAME = "conf/testserver.keytab";

        final String mech = "GSSAPI";   // TODO: should depend on zoo.cfg specified mechs.


        System.setProperty("java.security.auth.login.config", JAAS_CONF_FILE_NAME);

        //
        // The file given in JAAS_CONF_FILE_NAME must have :
        //
        // $SERVICE_SECTION_OF_JAAS_CONF_FILE {
        //   com.sun.security.auth.module.Krb5LoginModule required
        //   useKeyTab=true
        //   keyTab="$KEY_TAB_FILE_NAME"
        //   doNotPrompt=true
        //   useTicketCache=false
        //   storeKey=true
        //   debug=true
        //   principal="$SERVICE_NAME/$HOST_NAME";
        // };

        try {
            // 1. Login to Kerberos.
            LoginContext loginCtx = null;
            LOG.info("Authenticating using '" + SERVICE_SECTION_OF_JAAS_CONF_FILE + "' section of '" + JAAS_CONF_FILE_NAME + "'...");
            loginCtx = new LoginContext(SERVICE_SECTION_OF_JAAS_CONF_FILE);
            loginCtx.login();
            zkServerSubject = loginCtx.getSubject();
            LOG.info("Authenticated successfully with Kerberos server.");
        }
        catch (LoginException e) {
            System.err.println("LoginException: : " + e);
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public SaslServer createSaslServer() {
        Subject subject = getSubject();

        // SASL/Kerberos-related constants:
        // TODO: these are hardwired and redundant (see ZooKeeperMain.java and ClientCnxn.java); use zoo.cfg instead.
        final String JAAS_CONF_FILE_NAME = "jaas.conf";
        final String HOST_NAME = "ekoontz";
        final String SERVICE_PRINCIPAL_NAME = "testserver";
        final String SERVICE_SECTION_OF_JAAS_CONF_FILE = "Server";
        final String KEY_TAB_FILE_NAME = "conf/testserver.keytab";

        final String mech = "GSSAPI";   // TODO: should depend on zoo.cfg specified mechs.
        // or figure out how to mock up a Kerberos server.
        final String principalName = SERVICE_PRINCIPAL_NAME;
        final String hostName = HOST_NAME;

        try {
            return Subject.doAs(subject,new PrivilegedExceptionAction<SaslServer>() {
                public SaslServer run() {
                    try {
                        SaslServer saslServer;
                        saslServer = Sasl.createSaslServer(mech, principalName, hostName, null, new SaslServerCallbackHandler());
                        return saslServer;
                    }
                    catch (SaslException e) {
                        e.printStackTrace();
                        return null;
                    }
                }
            }
            );
        }
        catch (PrivilegedActionException e) {
            // TODO: exit server at this point(?)
            e.printStackTrace();
        }
        return null;
    }
}

class SaslServerCallbackHandler implements CallbackHandler {
    private static final Logger LOG = Logger.getLogger(ServerCallbackHandler.class);

    public void handle(Callback[] callbacks) throws
            UnsupportedCallbackException {
        LOG.debug("ServerCallbackHandler::handle()");
        AuthorizeCallback ac = null;
        for (Callback callback : callbacks) {
            if (callback instanceof AuthorizeCallback) {
                ac = (AuthorizeCallback) callback;
            } else {
                throw new UnsupportedCallbackException(callback,
                        "Unrecognized SASL GSSAPI Callback");
            }
        }
        if (ac != null) {
            String authenticationID = ac.getAuthenticationID();
            String authorizationID = ac.getAuthorizationID();

            LOG.info("Successfully authenticated client: authenticationID=" + authenticationID + ";  authorizationID=" + authorizationID + ".");
            if (authenticationID.equals(authorizationID)) {
                LOG.debug("setAuthorized(true) since " + authenticationID + "==" + authorizationID);
                ac.setAuthorized(true);
            } else {
                LOG.debug("setAuthorized(true), even though " + authenticationID + "!=" + authorizationID + ".");
                ac.setAuthorized(true);
            }
            if (ac.isAuthorized()) {
                LOG.debug("isAuthorized() since ac.isAuthorized() == true");
                ac.setAuthorizedID(authorizationID);
            }
        }
    }
}


