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
import org.apache.zookeeper.ZooKeeper.States;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

/**
 * This class manages SASL authentication and, optionally, encryption for the client. It
 * allows ClientCnxn to authenticate using SASL with a Zookeeper server and optionally encrypt
 * communication to it and decrypt communication from it.
 */
public class ZooKeeperSaslClient {
    private static final Logger LOG = LoggerFactory.getLogger(ZooKeeperSaslClient.class);
    private LoginThread loginThread;
    private SaslClient saslClient;

    private byte[] saslToken = new byte[0];
    private ClientCnxn cnxn;

    public ZooKeeperSaslClient(ClientCnxn cnxn, String serverPrincipal) {
        this.cnxn = cnxn;
        this.saslClient = createSaslClient(serverPrincipal);
    }

    public static class ServerSaslResponseCallback implements AsyncCallback.DataCallback {
        public void processResult(int rc, String path, Object ctx, byte data[], Stat stat) {
            // processResult() is used by ClientCnxn's sendThread to respond to
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

    private SaslClient createSaslClient(final String servicePrincipal) {
        int indexOf = servicePrincipal.indexOf("/");
        final String serviceName = servicePrincipal.substring(0, indexOf);
        final String serviceHostname = servicePrincipal.substring(indexOf+1,servicePrincipal.length());

        // zookeeper.client.ticket.renewal defaults to 19 hours (about 80% of 24 hours, which is a typical ticket expiry interval).
        loginThread = new LoginThread("Client",new ClientCallbackHandler(null),Integer.getInteger("zookeeper.client.ticket.renewal",19*60*60*1000));

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
                    // "zk-sasl-md5" is a hard-wired 'domain' parameter shared with zookeeper server code (see ServerCnxnFactory.java)
                    saslClient = Sasl.createSaslClient(mechs, username, serviceName, "zk-sasl-md5", null, new ClientCallbackHandler(password));
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
                                    SaslClient saslClient = Sasl.createSaslClient(mechs,clientPrincipalName,serviceName,serviceHostname,null,new ClientCallbackHandler(null));
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

    private void prepareSaslResponseToServer(byte[] serverToken) {
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

    private byte[] createSaslToken(final byte[] saslToken) throws SaslException {
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

    private void queueSaslPacket(byte[] saslToken) {
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

    public void close() {
        LOG.debug("ZookeeperSaslClient object is shutting down.");
        if (loginThread.isAlive()) {
            try {
               loginThread.interrupt();
               loginThread.join();
            }
            catch (InterruptedException e) {
                // catch e..
            }
        }
    }

    private boolean hasInitialResponse() {
        return saslClient.hasInitialResponse();
    }

    public States stateTransition(States state) {
        States returnState = state;
        switch(state) {
            case SASL_INITIAL:
                if (isComplete() == true) {
                    // It should never be possible for the client to be in
                    // SASL_INITIAL state with a saslClient being in Complete state.
                    LOG.warn("Unexpectedly, SASL negotiation object is in " +
                             "completed state, while client's state is in " +
                             "SASL_INITIAL state. Going to AUTH_FAILED without " +
                             "attempting SASL negotiation with Zookeeper Quorum " +
                             "member.");
                    returnState = States.AUTH_FAILED;
                }
                else {
                    if (hasInitialResponse() == true) {
                        LOG.debug("saslClient.hasInitialResponse()==true");
                        LOG.debug("hasInitialResponse() == true; (1) SASL token length = " + saslToken.length);
                        try {
                            saslToken = createSaslToken(saslToken);
                        }
                        catch (SaslException e) {
                            LOG.error("SASL authentication with Zookeeper Quorum member failed: " + e);
                            returnState = States.AUTH_FAILED;
                        }
                        if (saslToken == null) {
                            LOG.warn("SASL negotiation with Zookeeper Quorum member failed: saslToken is null.");
                            returnState = States.AUTH_FAILED;
                        }
                        else {
                            LOG.debug("hasInitialResponse() == true; (2) SASL token length = " + saslToken.length);
                            queueSaslPacket(saslToken);
                            returnState = States.SASL;
                        }
                    }
                    else {
                        LOG.debug("saslClient.hasInitialResponse()==false");
                        LOG.debug("sending empty SASL token to server.");
                        // send a blank initial token which will hopefully prompt the ZK server to start the
                        // real authentication process.
                        byte[] emptyToken = new byte[0];
                        queueSaslPacket(emptyToken);
                        returnState = States.SASL;
                    }
                }
                break;
            case SASL:
                if (isComplete() == true) {
                    // TODO : determine whether authentication failed or
                    // not. ZK server knows, but client (running this code here)
                    // does not.
                    returnState = States.CONNECTED;
                }
                else {
                  // nothing needed here: ServerSaslResponseCallback (above) will handle
                  // continued SASL negotiation until isComplete() is true.
                }
                break;
            default:
        } // switch(state)
        return returnState;
    }

    // CallbackHandler here refers to javax.security.auth.callback.CallbackHandler.
    // (not to be confused with packet callbacks like ServerSaslResponseCallback, defined above).
    public static class ClientCallbackHandler implements CallbackHandler {
        private String password = null;

        public ClientCallbackHandler(String password) {
            this.password = password;
        }

        public void handle(Callback[] callbacks) throws
          UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    NameCallback nc = (NameCallback) callback;
                    nc.setName(nc.getDefaultName());
                }
                else {
                    if (callback instanceof PasswordCallback) {
                        PasswordCallback pc = (PasswordCallback)callback;
                        pc.setPassword(this.password.toCharArray());
                    }
                    else {
                        if (callback instanceof RealmCallback) {
                            RealmCallback rc = (RealmCallback) callback;
                            rc.setText(rc.getDefaultText());
                        }
                        else {
                            if (callback instanceof AuthorizeCallback) {
                                AuthorizeCallback ac = (AuthorizeCallback) callback;
                                String authid = ac.getAuthenticationID();
                                String authzid = ac.getAuthorizationID();
                                if (authid.equals(authzid)) {
                                    ac.setAuthorized(true);
                                } else {
                                    ac.setAuthorized(false);
                                }
                                if (ac.isAuthorized()) {
                                    ac.setAuthorizedID(authzid);
                                }
                            }
                            else {
                                throw new UnsupportedCallbackException(callback,"Unrecognized SASL ClientCallback");
                            }
                        }
                    }
                }
            }
        }
    }


}
