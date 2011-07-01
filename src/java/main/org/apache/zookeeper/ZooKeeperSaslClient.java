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

import javax.security.auth.Subject;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.zookeeper.ClientCnxn;

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


}
