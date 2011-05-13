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

import static org.apache.zookeeper.test.ClientBase.CONNECTION_TIMEOUT;

import java.io.File;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.List;

import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.PortAssignment;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.ZKTestCase;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.Watcher.Event.KeeperState;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.ZooDefs.Ids;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Stat;
import org.apache.zookeeper.server.ServerCnxnFactory;
import org.apache.zookeeper.server.SyncRequestProcessor;
import org.apache.zookeeper.server.ZooKeeperServer;
import org.junit.Assert;
import org.junit.Test;

public class ACLCountTest extends ZKTestCase implements Watcher {
    private static final String HOSTPORT =
        "127.0.0.1:" + PortAssignment.unique();
    private volatile CountDownLatch startSignal;

    /**
     *
     * Create a node and add 2 ACL values to it:
     *
     * new ArrayList<ACL>() { {
     *   add(new ACL(ZooDefs.Perms.READ,ZooDefs.Ids.ANYONE_ID_UNSAFE));
     *   add(new ACL(ZooDefs.Perms.ALL,ZooDefs.Ids.AUTH_IDS));
     * }};
     *
     * Test is to make sure that there are exactly 2 ACLs for that node.
     *
     */
    @Test
    public void testAclCount() throws Exception {
        File tmpDir = ClientBase.createTmpDir();
        ClientBase.setupTestEnv();
        ZooKeeperServer zks = new ZooKeeperServer(tmpDir, tmpDir, 3000);
        SyncRequestProcessor.setSnapCount(1000);
        final int PORT = Integer.parseInt(HOSTPORT.split(":")[1]);
        ServerCnxnFactory f = ServerCnxnFactory.createFactory(PORT, -1);
        f.startup(zks);
        ZooKeeper zk;

        final ArrayList<ACL> CREATOR_ALL_AND_WORLD_READABLE =
          new ArrayList<ACL>() { {
            add(new ACL(ZooDefs.Perms.READ,ZooDefs.Ids.ANYONE_ID_UNSAFE));
            add(new ACL(ZooDefs.Perms.ALL,ZooDefs.Ids.AUTH_IDS));
        }};

        try {
         //   LOG.info("starting up the zookeeper server .. waiting");
            Assert.assertTrue("waiting for server being up",
                    ClientBase.waitForServerUp(HOSTPORT, CONNECTION_TIMEOUT));
            zk = new ZooKeeper(HOSTPORT, CONNECTION_TIMEOUT, this);

            zk.addAuthInfo("digest", "pat:test".getBytes());
            zk.setACL("/", Ids.CREATOR_ALL_ACL, -1);

            String path = "/path";

            try {
              Assert.assertEquals(2,CREATOR_ALL_AND_WORLD_READABLE.size());
            }
            catch (Exception e) {
        //      LOG.error("Something is fundamentally wrong with ArrayList's add() method. add()ing twice to an empty ArrayList should result in an ArrayList with 2 members.");
              throw e;
            }

            zk.create(path,path.getBytes(),CREATOR_ALL_AND_WORLD_READABLE,CreateMode.PERSISTENT);
            List<ACL> acls = zk.getACL("/path", new Stat());
            Assert.assertEquals(2,acls.size());
        }
        catch (Exception e) {
          // test failed somehow.
          Assert.assertTrue(false);
        }

        Assert.assertTrue(true);

    }


    /*
     * (non-Javadoc)
     *
     * @see org.apache.zookeeper.Watcher#process(org.apache.zookeeper.WatcherEvent)
     */
    public void process(WatchedEvent event) {
   //     LOG.info("Event:" + event.getState() + " " + event.getType() + " "
   //              + event.getPath());
        if (event.getState() == KeeperState.SyncConnected) {
            if (startSignal != null && startSignal.getCount() > 0) {
   //             LOG.info("startsignal.countDown()");
                startSignal.countDown();
            } else {
    //            LOG.warn("startsignal " + startSignal);
            }
        }
    }

}
