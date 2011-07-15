#!/bin/sh
# TODO: fold into ant (current) or maven (future).
# example usage:
#
#    repeat.sh QuorumPeerMainTest
test=$1

i=0
ant clean test-init
while [ "$?" -eq "0" ] ; do
  i=$((i+1))
   ant junit.run -Dtestcase=$test
done

echo "test:' $test ' failed on iteration $i."

