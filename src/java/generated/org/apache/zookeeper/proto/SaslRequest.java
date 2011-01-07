// TODO : automatically generate this file (currently created by hand).
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

package org.apache.zookeeper.proto;

import java.util.*;
import org.apache.jute.*;

public class SaslRequest implements Record {
  private byte[] token;
  public SaslRequest() {
  }
  public SaslRequest(byte[] clientToken) {
    this.token = clientToken;
  }

  public byte[] getToken() {
    return token;
  }

  public void serialize(OutputArchive a_, String tag) throws java.io.IOException {
    a_.startRecord(this,tag);
    a_.writeBuffer(token,"clienttoken");
    a_.endRecord(this,tag);
  }
  public void deserialize(InputArchive a_, String tag) throws java.io.IOException {
    a_.startRecord(tag);
    this.token = a_.readBuffer("clienttoken");
    a_.endRecord(tag);
}
  public String toString() {
    try {
      java.io.ByteArrayOutputStream s =
        new java.io.ByteArrayOutputStream();
      CsvOutputArchive a_ =
        new CsvOutputArchive(s);
        a_.startRecord(this,"");
        a_.writeBuffer(token,"clienttoken");
        a_.endRecord(this,"");
      return new String(s.toByteArray(), "UTF-8");
    } catch (Throwable ex) {
      ex.printStackTrace();
    }
    return "ERROR";
  }
  public void write(java.io.DataOutput out) throws java.io.IOException {
    BinaryOutputArchive archive = new BinaryOutputArchive(out);
    serialize(archive, "");
  }
  public void readFields(java.io.DataInput in) throws java.io.IOException {
    BinaryInputArchive archive = new BinaryInputArchive(in);
    deserialize(archive, "");
  }
  public int compareTo (Object peer_) throws ClassCastException {
    if (!(peer_ instanceof SaslClientToken)) {
      throw new ClassCastException("Comparing different types of records.");
    }
    SaslRequest peer = (SaslRequest) peer_;
    int ret = 0;

    byte[] my = token;
    byte[] ur = peer.token;
    ret = org.apache.jute.Utils.compareBytes(my,0,my.length,ur,0,ur.length);

    if (ret != 0) return ret;
     return ret;
  }

  public boolean equals(Object peer_) {
    if (!(peer_ instanceof SaslRequest)) {
      return false;
    }
    if (peer_ == this) {
      return true;
    }
    SaslRequest peer = (SaslRequest) peer_;
    boolean ret = false;
    ret = org.apache.jute.Utils.bufEquals(token,peer.token);
    if (!ret) return ret;
     return ret;
  }
  public int hashCode() {
    int result = 17; // TODO: figure out what this magic number is..
    int ret;
    ret = Arrays.toString(token).hashCode();
    result = 37*result + ret;
    return result;
  }
  public static String signature() {
    // TODO: figure out this encoding.
    return "LSaslRequest(B)";
  }
}
