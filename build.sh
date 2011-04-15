#!/bin/bash
ant clean jar
mvn install:install-file -DgroupId=org.apache.zookeeper -DartifactId=zookeeper -Dversion=3.4.0-tm-5 -Dpackaging=jar -Dfile=build/zookeeper-3.4.0-tm-5.jar

