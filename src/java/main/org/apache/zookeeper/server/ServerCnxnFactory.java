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
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.management.JMException;
import javax.naming.ConfigurationException;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import org.apache.log4j.Logger;
import org.apache.zookeeper.LoginThread;
import org.apache.zookeeper.jmx.MBeanRegistry;

public abstract class ServerCnxnFactory {

    LoginThread loginThread;

    protected LoginThread startLoginThread(int renewJaasLoginInterval) {
        if (System.getProperty("java.security.auth.login.config") != null) {
            this.saslServerCallbackHandler = new SaslServerCallbackHandler(Configuration.getConfiguration());
            loginThread = new LoginThread("Server",this.saslServerCallbackHandler,renewJaasLoginInterval);
            loginThread.start();
            return loginThread;
        }
        return null;
    }

    public static final String ZOOKEEPER_SERVER_CNXN_FACTORY = "zookeeper.serverCnxnFactory";

    public interface PacketProcessor {
        public void processPacket(ByteBuffer packet, ServerCnxn src);
    }

    Logger LOG = Logger.getLogger(ServerCnxnFactory.class);

    String requireClientAuthScheme = null;

    private SaslServerCallbackHandler saslServerCallbackHandler = null;

    // only used if SASL mechanism is DIGEST-MD5: if mech is GSSAPI, passwords are not stored in Zookeeper.
    public void addPrivateCredential(String username, String password) {
        saslServerCallbackHandler.addPrivateCredential(username, password);
    }

    /**
     * The buffer will cause the connection to be close when we do a send.
     */
    static final ByteBuffer closeConn = ByteBuffer.allocate(0);

    public abstract int getLocalPort();
    
    public abstract Iterable<ServerCnxn> getConnections();

    public abstract void closeSession(long sessionId);

    public void configure(InetSocketAddress addr,
            int maxClientCnxns) throws IOException {
        // requireClientAuthScheme is null: no client authentication scheme is required.
        this.configure(addr,maxClientCnxns,(String)null,0);
    }

    public abstract void configure(InetSocketAddress addr,
            int maxClientCnxns, String requireClientAuthScheme, int renewJaasLoginInterval) throws IOException;

    public String getRequireClientAuthScheme() { return requireClientAuthScheme; }

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

    public SaslServer createSaslServer() {
        if (loginThread == null) {
            return null;
        }
        synchronized (loginThread) {
            Subject subject = loginThread.getLogin().getSubject();
            if (subject != null) {
                // server is using a JAAS-authenticated subject: determine service principal name and hostname from zk server's subject.
                if (subject.getPrincipals().size() > 0) {
                    try {
                        final Object[] principals = subject.getPrincipals().toArray();
                        final Principal servicePrincipal = (Principal)principals[0];

                        // e.g. servicePrincipalNameAndHostname := "zookeeper/myhost.foo.com@FOO.COM"
                        final String servicePrincipalNameAndHostname = servicePrincipal.getName();

                        int indexOf = servicePrincipalNameAndHostname.indexOf("/");

                        // e.g. servicePrincipalName := "zookeeper"
                        final String servicePrincipalName = servicePrincipalNameAndHostname.substring(0, indexOf);

                        // e.g. serviceHostnameAndKerbDomain := "myhost.foo.com@FOO.COM"
                        final String serviceHostnameAndKerbDomain = servicePrincipalNameAndHostname.substring(indexOf+1,servicePrincipalNameAndHostname.length());

                        indexOf = serviceHostnameAndKerbDomain.indexOf("@");
                        // e.g. serviceHostname := "myhost.foo.com"
                        final String serviceHostname = serviceHostnameAndKerbDomain.substring(0,indexOf);

                        final String mech = "GSSAPI";   // TODO: should depend on zoo.cfg specified mechs, but if subject is non-null, it can be assumed to be GSSAPI.

                        try {
                            return Subject.doAs(subject,new PrivilegedExceptionAction<SaslServer>() {
                                public SaslServer run() {
                                    try {
                                        SaslServer saslServer;
                                        saslServer = Sasl.createSaslServer(mech, servicePrincipalName, serviceHostname, null, saslServerCallbackHandler);
                                        return saslServer;
                                    }
                                    catch (SaslException e) {
                                        LOG.error("Zookeeper Quorum Member failed to create a SaslServer to interact with a client during session initiation: " + e);
                                        e.printStackTrace();
                                        return null;
                                    }
                                }
                            }
                            );
                        }
                        catch (PrivilegedActionException e) {
                            // TODO: exit server at this point(?)
                            LOG.error("Zookeeper Quorum member experienced a PrivilegedActionException exception while creating a SaslServer using a JAAS principal context:" + e);
                            e.printStackTrace();
                        }
                    }
                    catch (Exception e) {
                        LOG.error("server principal name/hostname determination error: " + e);
                    }
                }
                else {
                    // JAAS non-GSSAPI authentication: assuming and supporting only DIGEST-MD5 mechanism for now.
                    // TODO: use 'authMech=' value in zoo.cfg.
                    try {
                        SaslServer saslServer = Sasl.createSaslServer("DIGEST-MD5","zookeeper","zk-sasl-md5",null, saslServerCallbackHandler);
                        return saslServer;
                    }
                    catch (SaslException e) {
                        LOG.error("Zookeeper Quorum member failed to create a SaslServer to interact with a client during session initiation: " + e);
                    }
                }
            }
        }
        return null;
    }

    public abstract void closeAll();
    
    static public ServerCnxnFactory createFactory() throws IOException
    {
        String serverCnxnFactoryName =
            System.getProperty(ZOOKEEPER_SERVER_CNXN_FACTORY);
        if (serverCnxnFactoryName == null) {
            serverCnxnFactoryName = NIOServerCnxnFactory.class.getName();
        }
        try {
            return (ServerCnxnFactory)Class.forName(serverCnxnFactoryName).newInstance();
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
        return createFactory(new InetSocketAddress(clientPort), maxClientCnxns, null, 0);
    }

    static public ServerCnxnFactory createFactory(int clientPort,
            int maxClientCnxns, String requireClientAuthScheme, int renewJaasLoginInterval) throws IOException
    {
        return createFactory(new InetSocketAddress(clientPort), maxClientCnxns, requireClientAuthScheme, renewJaasLoginInterval);
    }

    static public ServerCnxnFactory createFactory(InetSocketAddress addr,
            int maxClientCnxns, String requireClientAuthScheme, int renewJaasLoginInterval) throws IOException
    {
        ServerCnxnFactory factory = createFactory();
        factory.configure(addr, maxClientCnxns, requireClientAuthScheme, renewJaasLoginInterval);
        return factory;
    }

    static public ServerCnxnFactory createFactory(InetSocketAddress addr,
            int maxClientCnxns) throws IOException
    {
        ServerCnxnFactory factory = createFactory();
        factory.configure(addr, maxClientCnxns, null,0);
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

    public class SaslServerCallbackHandler implements CallbackHandler {
        private String userName = null;
        private Map<String,String> credentials = new HashMap<String,String>();

        public SaslServerCallbackHandler(Configuration configuration) {
            AppConfigurationEntry configurationEntries[] = configuration.getAppConfigurationEntry("Server");

            if (configurationEntries == null) {
                String errorMessage = "could not find a 'Server' entry in this configuration: server cannot start.";
                LOG.error(errorMessage);
                throw(new NullPointerException(errorMessage));
            }
            credentials.clear();
            for(AppConfigurationEntry entry: configurationEntries) {
                Map<String,?> options = entry.getOptions();
                // Populate DIGEST-MD5 user -> password map with JAAS configuration entries from the "Server" section.
                // Usernames are distinguished from other options by prefixing the username with a "user_" prefix.
                Iterator it = options.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry pair = (Map.Entry)it.next();
                    String key = (String)pair.getKey();
                    if (key.substring(0,5).equals("user_")) {
                        String userName = key.substring(5);
                        credentials.put(userName,(String)pair.getValue());
                    }
                }
            }
            return;
        }

        public void addPrivateCredential(String username, String password) {
            this.credentials.put(username,password);
        }

        public void handle(Callback[] callbacks) throws
                UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    NameCallback nc = (NameCallback) callback;
                    // check to see if this user is in the user password database.
                    if (credentials.get(nc.getDefaultName()) != null) {
                        nc.setName(nc.getDefaultName());
                        this.userName = nc.getDefaultName();
                    }
                    else { // no such user.
                        LOG.warn("User '" + nc.getDefaultName() + "' not found in list of DIGEST-MD5 authenticateable users.");
                    }
                }
                else {
                    if (callback instanceof PasswordCallback) {
                        PasswordCallback pc = (PasswordCallback) callback;

                        if ((this.userName.equals("super")
                                &&
                                (System.getProperty("zookeeper.SASLAuthenticationProvider.superPassword") != null))) {
                            // superuser: use Java system property for password, if available.
                            pc.setPassword(System.getProperty("zookeeper.SASLAuthenticationProvider.superPassword").toCharArray());
                        }
                        else {
                            if (this.credentials.get(this.userName) != null) {
                                pc.setPassword(this.credentials.get(this.userName).toCharArray());
                            }
                            else {
                                LOG.warn("No password found for user: " + this.userName);
                            }
                        }
                    }
                    else {
                        if (callback instanceof RealmCallback) {
                            RealmCallback rc = (RealmCallback) callback;
                            LOG.debug("client supplied realm: " + rc.getDefaultText());
                            rc.setText(rc.getDefaultText());
                        }
                        else {
                            if (callback instanceof AuthorizeCallback) {
                                AuthorizeCallback ac = (AuthorizeCallback) callback;

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
                }
            }
        }
    }
}



