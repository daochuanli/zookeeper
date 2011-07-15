#!/bin/sh
# TODO: fold into ant (current) or maven (future).
# example usage (run in top-level zookeeper directory) :
#
#    src/repeat.sh ZooKeeperTest
test_output=yes
testcase=$1

i=0
ant test-init
while [ "$?" -eq "0" ] ; do
  i=`expr $i + 1`
  ant -Dtest.output=$test_output -Dtestcase=$testcase junit.run
done

echo "test:' $testcase ' failed on iteration $i."

