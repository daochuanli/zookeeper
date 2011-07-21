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
import java.util.HashMap;

import javax.management.JMException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.zookeeper.jmx.MBeanRegistry;
import org.apache.zookeeper.Login;

public abstract class ServerCnxnFactory {

    public static final String ZOOKEEPER_SERVER_CNXN_FACTORY = "zookeeper.serverCnxnFactory";

    public interface PacketProcessor {
        public void processPacket(ByteBuffer packet, ServerCnxn src);
    }
    
    Logger LOG = LoggerFactory.getLogger(ServerCnxnFactory.class);

    /**
     * The buffer will cause the connection to be close when we do a send.
     */
    static final ByteBuffer closeConn = ByteBuffer.allocate(0);

    public abstract int getLocalPort();
    
    public abstract Iterable<ServerCnxn> getConnections();

    public abstract void closeSession(long sessionId);

    public abstract void configure(InetSocketAddress addr,
                                   int maxClientCnxns) throws IOException;

    public String requireClientAuthScheme = null;

    private SaslServerCallbackHandler saslServerCallbackHandler;
    public Login login;

    public void configure(InetSocketAddress addr, int maxClientCnxns, String requireClientAuthScheme) throws IOException {
        this.requireClientAuthScheme = requireClientAuthScheme;
        // Use presence/absence of java.security.auth.login.config property
        // as a boolean flag to decide where to obtain login credentials.
        if (System.getProperty("java.security.auth.login.config") != null) {
            saslServerCallbackHandler = new SaslServerCallbackHandler(Configuration.getConfiguration());
            try {
                login = new Login("Server",saslServerCallbackHandler);
            }
            catch (LoginException e) {
                throw new IOException("Could not configure server because SASL configuration did not allow the "
                  + " Zookeeper server to authenticate itself properly: " + e);
            }
        }
        configure(addr,maxClientCnxns);  
    }

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
        return createFactory(new InetSocketAddress(clientPort), maxClientCnxns,null);
    }

    static public ServerCnxnFactory createFactory(int clientPort,
            int maxClientCnxns, String requireClientAuthScheme) throws IOException
    {
        return createFactory(new InetSocketAddress(clientPort), maxClientCnxns, requireClientAuthScheme);
    }

    static public ServerCnxnFactory createFactory(InetSocketAddress addr,
            int maxClientCnxns, String requireClientAuthScheme) throws IOException
    {
        ServerCnxnFactory factory = createFactory();
        factory.configure(addr, maxClientCnxns, requireClientAuthScheme);
        return factory;
    }

    static public ServerCnxnFactory createFactory(InetSocketAddress addr,
            int maxClientCnxns) throws IOException {
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

}
