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

import org.apache.zookeeper.*;
import org.apache.zookeeper.Watcher.Event.KeeperState;
import org.apache.zookeeper.ZooDefs.Ids;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Stat;
import org.apache.zookeeper.server.ServerCnxnFactory;
import org.apache.zookeeper.server.SyncRequestProcessor;
import org.apache.zookeeper.server.ZooKeeperServer;
import org.junit.Assert;
import org.junit.Test;

public class ACLOrderingTest extends ZKTestCase implements Watcher {
    private static final String HOSTPORT =
        "127.0.0.1:" + PortAssignment.unique();
    private volatile CountDownLatch startSignal;

    /**
     *
     * Create two nodes. With one, add :
     *
     * new ArrayList<ACL>() { {
     *   add(new ACL(ZooDefs.Perms.READ,ZooDefs.Ids.ANYONE_ID_UNSAFE));
     *   add(new ACL(ZooDefs.Perms.ALL,ZooDefs.Ids.AUTH_IDS));
     * }};
     *
     * to the other, add:
     *
     * new ArrayList<ACL>() { {
     *   add(new ACL(ZooDefs.Perms.ALL,ZooDefs.Ids.AUTH_IDS));
     *   add(new ACL(ZooDefs.Perms.READ,ZooDefs.Ids.ANYONE_ID_UNSAFE));
     * }};
     *
     *
     * Test is to make sure that both nodes have equivalent ACL semantics.
     *
     */
    @Test
    public void testAclOrdering() throws Exception {
        File tmpDir = ClientBase.createTmpDir();
        ClientBase.setupTestEnv();
        ZooKeeperServer zks = new ZooKeeperServer(tmpDir, tmpDir, 3000);
        SyncRequestProcessor.setSnapCount(1000);
        final int PORT = Integer.parseInt(HOSTPORT.split(":")[1]);
        ServerCnxnFactory f = ServerCnxnFactory.createFactory(PORT, -1);
        f.startup(zks);
        ZooKeeper creator;
        ZooKeeper anonymous;
        ZooKeeper creator2;

        final ArrayList<ACL> CREATOR_ALL_AND_WORLD_READABLE =
          new ArrayList<ACL>() { {
            add(new ACL(ZooDefs.Perms.READ,ZooDefs.Ids.ANYONE_ID_UNSAFE));
            add(new ACL(ZooDefs.Perms.ALL,ZooDefs.Ids.AUTH_IDS));
        }};

        final ArrayList<ACL> WORLD_READABLE_AND_CREATOR_ALL =
          new ArrayList<ACL>() { {
            add(new ACL(ZooDefs.Perms.ALL,ZooDefs.Ids.AUTH_IDS));
            add(new ACL(ZooDefs.Perms.READ,ZooDefs.Ids.ANYONE_ID_UNSAFE));
        }};

        try {
            Assert.assertTrue("waiting for server being up",
                    ClientBase.waitForServerUp(HOSTPORT, CONNECTION_TIMEOUT));
            creator = new ZooKeeper(HOSTPORT, CONNECTION_TIMEOUT, this);

            creator.addAuthInfo("digest", "pat:test".getBytes());
            creator.setACL("/", Ids.CREATOR_ALL_ACL, -1);

            String path1 = "/path1";
            creator.create(path1,path1.getBytes(),CREATOR_ALL_AND_WORLD_READABLE,CreateMode.PERSISTENT);

            String path2 = "/path2";
            creator.create(path2,path2.getBytes(),WORLD_READABLE_AND_CREATOR_ALL,CreateMode.PERSISTENT);

            anonymous = new ZooKeeper(HOSTPORT, CONNECTION_TIMEOUT, this);

            // test readability: should succeed for both since both are world-readable.
            anonymous.getData("/path1", false, null);
            anonymous.getData("/path2", false, null);

            // test writeability for both path1 and path2: should fail for both.
            try {
               anonymous.setData("/path1","overwrite attempt".getBytes(),0);
            }
            catch (KeeperException.NoAuthException e) {
               //LOG.info("As expected, anonymous client could not write to /path1.");
            }
            try {
               anonymous.setData("/path2","overwrite attempt".getBytes(),0);
            }
            catch (KeeperException.NoAuthException e) {
               //LOG.info("As expected, anonymous client could not write to /path2.");
            }

            // test deleteability for both path1 and path2: should also fail for both.
            try {
               anonymous.delete("/path1",1);
            }
            catch (KeeperException.NoAuthException e) {
               //LOG.info("As expected, anonymous client could not delete /path1.");
            }

            try {
               anonymous.delete("/path2",1);
            }
            catch (KeeperException.NoAuthException e) {
               //LOG.info("As expected, anonymous client could not delete /path2.");
            }


            creator2 = new ZooKeeper(HOSTPORT, CONNECTION_TIMEOUT, this);
            creator2.addAuthInfo("digest", "pat:test".getBytes());

            // test readablilty: should succeed for both.
            creator2.getData("/path1", false, null);
            creator2.getData("/path2", false, null);

            // test writeability: should succeed for both.
            creator2.setData("/path1","overwrite attempt".getBytes(),0);
            creator2.setData("/path2","overwrite attempt".getBytes(),0);

            // test deletability: should succeed for both.
            creator2.delete("/path1",1);
            creator2.delete("/path2",1);

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
        //LOG.info("Event:" + event.getState() + " " + event.getType() + " "
         //        + event.getPath());
        if (event.getState() == KeeperState.SyncConnected) {
            if (startSignal != null && startSignal.getCount() > 0) {
          //      LOG.info("startsignal.countDown()");
                startSignal.countDown();
            } else {
          //      LOG.warn("startsignal " + startSignal);
            }
        }
    }
}
