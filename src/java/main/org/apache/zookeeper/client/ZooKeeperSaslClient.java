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

package org.apache.zookeeper.client;

import javax.security.auth.Subject;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.apache.zookeeper.AsyncCallback;
import org.apache.zookeeper.ClientCnxn;
import org.apache.zookeeper.LoginThread;
import org.apache.zookeeper.data.Stat;
import org.apache.zookeeper.proto.GetSASLRequest;
import org.apache.zookeeper.proto.ReplyHeader;
import org.apache.zookeeper.proto.RequestHeader;
import org.apache.zookeeper.proto.SetSASLResponse;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.ZooKeeper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * This class manages SASL authentication and, optionally, encryption for the client. It
 * allows ClientCnxn to authenticate using SASL with a Zookeeper server and optionally encrypt
 * communication to it and decrypt communication from it.
 */
public class ZooKeeperSaslClient {
    private static final Logger LOG = LoggerFactory.getLogger(ZooKeeperSaslClient.class);
    private LoginThread loginThread;
    private SaslClient saslClient;
    // TODO: will be private when more
    // more SASL processing is moved out of ClientCnxn.run() to here.
    public byte[] saslToken = new byte[0];
    private ClientCnxn cnxn;

    public ZooKeeperSaslClient(ClientCnxn cnxn, String serverPrincipal, LoginThread loginThread) {
      this.cnxn = cnxn;
      this.loginThread = loginThread;
      this.saslClient = createSaslClient(serverPrincipal,loginThread);
    }

    private static SaslClient createSaslClient(final String servicePrincipal, LoginThread loginThread) {

        int indexOf = servicePrincipal.indexOf("/");

        final String serviceName = servicePrincipal.substring(0, indexOf);
        final String serviceHostname = servicePrincipal.substring(indexOf+1,servicePrincipal.length());

        try {
            if (loginThread.isAlive() == false) {
              loginThread.start();
            }
            synchronized(loginThread) {
                Subject subject = loginThread.getLogin().getSubject();
                SaslClient saslClient = null;
                // Use subject.getPrincipals().isEmpty() as an indication of which SASL mechanism to use: if empty, use DIGEST-MD5; otherwise, use GSSAPI.
                if (subject.getPrincipals().isEmpty() == true) {
                    // no principals: must not be GSSAPI: use DIGEST-MD5 mechanism instead.
                    LOG.info("Client will use DIGEST-MD5 as SASL mechanism.");
                    String[] mechs = {"DIGEST-MD5"};
                    String username = (String)(subject.getPublicCredentials().toArray()[0]);
                    String password = (String)(subject.getPrivateCredentials().toArray()[0]);
                    // "zk-sasl-md5" is a hard-wired 'domain' parameter used also by server.
                    saslClient = Sasl.createSaslClient(mechs, username, serviceName, "zk-sasl-md5", null, new ZooKeeper.ClientCallbackHandler(password));
                    return saslClient;
                }
                else { // GSSAPI.
                    final Object[] principals = subject.getPrincipals().toArray();
                    // determine client principal from subject.
                    final Principal clientPrincipal = (Principal)principals[0];
                    final String clientPrincipalName = clientPrincipal.getName();

                    try {
                        saslClient = Subject.doAs(subject,new PrivilegedExceptionAction<SaslClient>() {
                                public SaslClient run() throws SaslException {
                                    LOG.info("Client will use GSSAPI as SASL mechanism.");
                                    String[] mechs = {"GSSAPI"};
                                    LOG.debug("creating sasl client: client="+clientPrincipalName+";service="+serviceName+";serviceHostname="+serviceHostname);
                                    SaslClient saslClient = Sasl.createSaslClient(mechs,clientPrincipalName,serviceName,serviceHostname,null,new ZooKeeper.ClientCallbackHandler(null));
                                    return saslClient;
                                }
                            });
                        return saslClient;
                    }
                    catch (Exception e) {
                        LOG.error("Error creating SASL client:" + e);
                        e.printStackTrace();
                        return null;
                    }
                }
            }
        }
        catch (Exception e) {
            LOG.error("Exception while trying to create SASL client: " + e);
            return null;
        }
    }


    public void prepareSaslResponseToServer(byte[] serverToken) {
        saslToken = serverToken;

        LOG.debug("saslToken (server) length: " + saslToken.length);

        if (!(saslClient.isComplete() == true)) {
            try {
                saslToken = createSaslToken(saslToken);
                if (saslToken != null) {
                    LOG.debug("saslToken (client) length: " + saslToken.length);
                    queueSaslPacket(saslToken);
                }

                if (saslClient.isComplete() == true) {
                    LOG.info("SASL authentication with Zookeeper server is successful.");
                    cnxn.queueEvent(new WatchedEvent(
                      Watcher.Event.EventType.None,
                      Watcher.Event.KeeperState.SaslAuthenticated, null));
                }

            } catch (SaslException e) {
                // TODO sendThread should set state to AUTH_FAILED; but currently only sendThread modifies state.
                LOG.error("SASL authentication failed.");
            }
        }
    }

    public byte[] createSaslToken(final byte[] saslToken) throws SaslException {
        if (saslToken == null) {
            // TODO: introspect about runtime environment (such as jaas.conf)
            throw new SaslException("Error in authenticating with a Zookeeper Quorum member: the quorum member's saslToken is null.");
        }

        Subject subject = this.loginThread.getLogin().getSubject();
        if (subject != null) {
            synchronized(this.loginThread) {
                try {
                    final byte[] retval =
                        Subject.doAs(subject, new PrivilegedExceptionAction<byte[]>() {
                                public byte[] run() throws SaslException {
                                    try {
                                        LOG.debug("saslClient.evaluateChallenge(len="+saslToken.length+")");
                                        return saslClient.evaluateChallenge(saslToken);
                                    }
                                    catch (NullPointerException e) {
                                        LOG.error("Quorum Member's SASL challenge was null.");
                                    }
                                    // NOTE: saslClient.evaluateChallenge() will throw a SaslException if authentication fails.
                                    // returning null here will cause another (new) SaslException to be thrown.
                                    return null;
                                }
                            });

                    if (retval != null) {
                        LOG.debug("Successfully created token with length:"+retval.length);
                    }

                    return retval;
                }
                catch (PrivilegedActionException e) {
                    LOG.error("An error: " + e + " occurred when evaluating Zookeeper Quorum Member's received SASL token. Client will go to AUTH_FAILED state.");
                    throw new SaslException("An error: " + e + " occurred when evaluating Zookeeper Quorum Member's received SASL token. Client will go to AUTH_FAILED state.");
                }
            }
        }
        else {
            throw new SaslException("Cannot make SASL TOKEN without subject defined.");
        }
    }

    public static class ServerSaslResponseCallback implements AsyncCallback.DataCallback {
        public void processResult(int rc, String path, Object ctx, byte data[], Stat stat) {
            // data[] contains the Zookeeper Server's SASL token.
            // ctx is the ZooKeeperSaslClient object. We use this object's prepareSaslResponseToServer() method
            // to reply to the Zookeeper Server's SASL token
            ZooKeeperSaslClient client = ((ClientCnxn)ctx).zooKeeperSaslClient;
            byte[] usedata = data;
            if (data != null) {
                LOG.debug("ServerSaslResponseCallback(): saslToken server response: (length="+usedata.length+")");
            }
            else {
                usedata = new byte[0];
                LOG.debug("ServerSaslResponseCallback(): using empty data[] as server response (length="+usedata.length+")");
            }
            client.prepareSaslResponseToServer(usedata);
        }
    }

    // TODO: make private once more sasl code is extracted from
    // ClientCnxn.run().
    public void queueSaslPacket(byte[] saslToken) {
        LOG.info("cnxn: " + cnxn.toString());
        LOG.info("ClientCnxn:sendSaslPacket:length="+saslToken.length);
        RequestHeader h = new RequestHeader();
        h.setType(ZooDefs.OpCode.sasl);
        GetSASLRequest request = new GetSASLRequest();
        request.setToken(saslToken);
        SetSASLResponse response = new SetSASLResponse();

        ServerSaslResponseCallback cb = new ServerSaslResponseCallback();

        ReplyHeader r = new ReplyHeader();
        cnxn.queuePacket(h,r,request,response,cb);
    }

    public boolean isComplete() {
        return saslClient.isComplete();
    }

    public boolean hasInitialResponse() {
        return saslClient.hasInitialResponse();
    }

}
