# ZK Quorum Auth Tutorial

This document describes how to use the quorum authentication using sasl.
ZooKeeper supports DIGEST-MD5 or Kerberos as your authentication mechanism.
ZooKeeper Servers will talk to each other using the credentials configured in
the jaas.conf file. They will act like client-server when creating connections.

## Server Configurations

###conf/zoo.cfg
Set JVMFLAGS to use `jaas.conf`
```
java.security.auth.login.config=$JAASCONF_DIR/jaas.conf
```
Change `$JAASCONF_DIR` to the directory where `jaas.conf` is.

Set to enable quorum authentication using sasl (No Java system property).
Defaulting to false.
```
quorum.auth.enableSasl=false
```

Set to connect using quorum authentication is optional (No Java system property)
If this is false, quorum peer client will talk to other quorum peer server without authentication.
This can be used while upgrading the ZooKeeper server. Defaulting to false.
```
quorum.auth.learnerRequireSasl=false
```

Set to connect using quorum authentication is optional (No Java system property)
If this is false, quorum peer server will accept another quorum peer client connection even if
the authentication did not succeed. This can be used while upgrading the ZooKeeper server.
Defaulting to false.
```
quorum.auth.serverRequireSasl=false
```

(Optional) If you want to use different login context for client/server,
set flags: (No Java system property)
```
quorum.auth.client.loginContext=".. Client Login Context ..Defaulting to QuorumClient"
quorum.auth.server.loginContext=".. Server Login Context ..Defaulting to QuorumServer"
```

quorum.auth.kerberos.servicePrincipal=".. Service Principal ..Defaulting to zkquorum/localhost"


java.security.auth.login.config should be either DIGEST-MD5 or Kerberos authentication mechanism.
Following are the examples of the jaas.conf file:

###JAAS configuration file: DIGEST-MD5 authentication

```
QuorumServer {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    user_test="test";
};
QuorumClient {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    username="test"
    password="test";
};
```

###JAAS configuration file: Kerberos authentication

```
QuorumServer {
       com.sun.security.auth.module.Krb5LoginModule required
       useKeyTab=true
       keyTab="/path/to/keytab"
       storeKey=true
       useTicketCache=false
       debug=false
       principal="zkquorum/localhost@EXAMPLE.COM";
};
QuorumLearner {
       com.sun.security.auth.module.Krb5LoginModule required
       useKeyTab=true
       keyTab="/path/to/keytab"
       storeKey=true
       useTicketCache=false
       debug=false
       principal="client@EXAMPLE.COM";
};
```

(Optional) For using Kerberos, also recommends setting JVM flags:
```
javax.security.auth.useSubjectCredsOnly=false
```

(Optional) For using Kerberos, you can change service principal by setting flags: (No Java system property).
Reference Links:-
http://docs.oracle.com/javase/7/docs/technotes/guides/security/jgss/tutorials/Troubleshooting.html
http://docs.oracle.com/javase/7/docs/technotes/guides/security/jgss/tutorials/BasicClientServer.html
