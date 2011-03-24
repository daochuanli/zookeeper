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

package org.apache.zookeeper.test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.TestableZooKeeper;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.Watcher.Event.KeeperState;
import org.apache.zookeeper.ZooDefs.Ids;
import org.junit.Test;

public class SaslAuthTest extends ClientBase {
    static {
        System.setProperty("zookeeper.authProvider.1","org.apache.zookeeper.server.auth.SASLAuthenticationProvider");

        try {
            File tmpDir = createTmpDir();
            File saslConfFile = new File(tmpDir, "jaas.conf");
            FileWriter fwriter = new FileWriter(saslConfFile);

            fwriter.write("" +
                    "Server {\n" +
                    "          org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                    "          user_super=\"test\";\n" +
                    "};\n" +
                    "Client {\n" +
                    "       org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                    "       username=\"super\"\n" +
                    "       password=\"test\";\n" +
                    "};" + "\n");
            fwriter.close();
            System.setProperty("java.security.auth.login.config",saslConfFile.getAbsolutePath());
        }
        catch (IOException e) {
            // could not create tmp directory to hold JAAS conf file : test will fail now.
        }
    }

    private AtomicInteger authFailed = new AtomicInteger(0);
    
    @Override
    protected TestableZooKeeper createClient(String hp)
    throws IOException, InterruptedException
    {
        File tmpDir = ClientBase.createTmpDir();
        File saslConfFile = new File(tmpDir, "jaas.conf");
        FileWriter fwriter = new FileWriter(saslConfFile);

        fwriter.write("" +
                "Server {\n" +
                "          org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                "          user_super=\"test\";\n" +
                "};\n" +
                "Client {\n" +
                "       org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                "       username=\"super\"\n" +
                "       password=\"test\";\n" +
                "};" + "\n");
        fwriter.close();
        System.setProperty("java.security.auth.login.config",saslConfFile.getAbsolutePath());
        MyWatcher watcher = new MyWatcher();
        return createClient(watcher, hp);
    }

    private class MyWatcher extends CountdownWatcher {
        @Override
        public synchronized void process(WatchedEvent event) {
            if (event.getState() == KeeperState.AuthFailed) {
                authFailed.incrementAndGet();
            }
            else {
                super.process(event);
            }
        }
    }

    @Test
    public void testBadSaslAuthNotifiesWatch() throws Exception {
        ZooKeeper zk = createClient();
        Thread.sleep(1000);
        zk.close();
    }

    
    @Test
    public void testAuth() throws Exception {
        ZooKeeper zk = createClient();
        Thread.sleep(1000);
        try {
            zk.create("/path1", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
            Thread.sleep(1000);
        } finally {
            zk.close();
        }
    }
}
