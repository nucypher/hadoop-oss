NuCypher hadoop components

In this repository set ot NuCypher hadoop componetns can be found.

The list of essential components:

nucypher-crypto - crypto alghorithms for deligates access implementation
nucypher-hadoop-common - modified hadoop core framework with support for public/private key pairs and deligated access
nucypher-kms - set of KMS-based daemons for deligated access
nucypher-hadoop-plugins - plugin to support bulk files' attributes mofication with single RPC call
nucypher-keyrotation - simple utility for distributed key rotation

INSTALLATION

There are three kind of nodes in NuCypher KMS service

GlobalKMS - main storage of keys
LocalKMS -  proxy KMS, should be located on any host, which will use KMS to access data
REN - ReEncryption Node - special daemon used to hold re-encryption keys, which converts global keys to local ones.
      We should have number of such nodes, to balance load. They should be located on separate hosts from LocalKMSes and GlobalKMS

Daemons can be started with
$NUCYPHER_KMS_PREFIX/sbin/kms.sh start

--Daemons common configuration:

Following enviromental variables should be set:
NUCYPHER_KMS_PREFIX should point to the directory NuCypher KMS service is installed on host
NUCYPHER_KMS_CONF_DIR should point to the directory with specific daemon configuration, ie core-site.xml, kms-site.xml and related files can be found
optionaly HADOOP_LOG_DIR can be set ot directory with logs
HADOOP_CATALINA_PREFIX & HADOOP_IDENT_STRING can be set ot daemon names to get correct log file naming

Sample configuration files can be found in nucypher-kms/src/main/conf directory. They should be placed to appropriate configuration directory

kms-acls.xml - ACL file with special tokens for deligated access
kms-env.sh - env config for GlobaKMS
kms-site.xml - main config for GlobalKMS
log4j.properties - common log config for GlobalKMS
kms-log4j.properties - log config for GlobalKMS

kms-env.local-kms.sh - env config for LocalKMS
kms-site.local-kms.xml - main config for LocalKMS
kms-log4j.local-kms.properties - log configuration for LocalKMS

kms-env.ren.sh - env config for REN
kms-site.ren.xml - kms-site.xml config file for REN
kms-log4j.ren.properties - log configuration for REN


--GlobalKMS configuration:

kms-site.xml
Path to keystore should be setup here:

 <property>
    <name>hadoop.kms.key.provider.uri</name>
    <value>jcekps://file@/${user.home}/kms.keystore</value>
    <description>
      URI of the backing KeyProvider for the KMS.
    </description>
 </property>

Also special setup for crypto codecs required:

<property>
    <name>hadoop.security.crypto.codec.classes.bbs98.none.padding</name>
    <value>org.apache.hadoop.crypto.BBS98BCCryptoCodec</value>
</property>
<property>
    <name>hadoop.security.crypto.cipher.suite</name>
    <value>BBS98/None/Padding</value>
</property>

--LocalKMS configuration:

kms-site.xml:

Here should be set mode of current NuCypher KMS daemon, LOCAL_KMS
<property>
    <name>hadoop.kms.mode</name>
    <value>LOCAL_KMS</value>
</property>

Also, REN and GlobalKMS addresses should be set:

<property>
    <name>hadoop.kms.re.key.provider.uri</name>
    <value>ren://http@localhost:16110/kms</value>
</property>
<property>
    <name>hadoop.kms.key.provider.uri</name>
    <value>prekms://http@localhost:16000/kms</value>
    <description>
      URI of the backing KeyProvider for the KMS.
    </description>
</property>

crypto codecs setup:
<property>
        <name>hadoop.security.crypto.codec.classes.bbs98.none.padding</name>
        <value>org.apache.hadoop.crypto.BBS98BCCryptoCodec</value>
</property>

cipher setup:

<!-- KeyProvider.DEFAULT_CIPHER_NAME Used to encrypt and decrypt data-->
<property>
        <name>hadoop.security.key.default.cipher</name>
	<value>AES/CTR/NoPadding</value>
</property>

<!-- CommonConfigurationKeysPublic.HADOOP_SECURITY_CRYPTO_CIPHER_SUITE_KEY
Used to encrypt and decrypt DEK -->
<property>
        <name>hadoop.security.crypto.cipher.suite</name>
        <value>BBS98/None/Padding</value>
</property>

--REN configuration:

kms-env.sh:
mode should be set

<property>
    <name>hadoop.kms.mode</name>
    <value>RE_NODE</value>
</property>

here we set keys are stored in memory only
<property>
    <name>hadoop.kms.re.key.provider.uri</name>
	 <value>memren://file@/${user.home}/some.fake.file.path</value>
</property>

set address of GlobalKMS
<property>
    <name>hadoop.kms.key.provider.uri</name>
    <value>prekms://http@localhost:16000/kms</value>
    <description>
      URI of the backing KeyProvider for the KMS.
    </description>
</property>

codecs and cipher setup:

<property>
        <name>hadoop.security.crypto.codec.classes.bbs98.none.padding</name>
        <value>org.apache.hadoop.crypto.BBS98BCCryptoCodec</value>
</property>
<property>
        <name>hadoop.security.crypto.codec.classes.bbs98re.none.nopadding</name>
        <value>org.apache.hadoop.crypto.BBS98BCTransformationCryptoCodec</value>
</property>
<!-- KeyProvider.DEFAULT_CIPHER_NAME Used to encrypt and decrypt data-->
<property>
        <name>hadoop.security.key.default.cipher</name>
	<value>AES/CTR/NoPadding</value>
</property>
<!-- CommonConfigurationKeysPublic.HADOOP_SECURITY_CRYPTO_CIPHER_SUITE_KEY
Used to encrypt and decrypt DEK -->
<property>
	<name>hadoop.ren.re.enc.suite</name>
        <value>BBS98RE/None/NoPadding</value>
</property>

-- Hadoop nodes configuration

main change should be made, we should set address of LocalKMS, located on the same node:
core-site.xml:

<property>
  <name>hadoop.security.key.provider.path</name>
  <value>kms://http@localhost:16000/kms</value>
  <description>
    The KeyProvider to use when interacting with encryption keys used
    when reading and writing to an encryption zone.
  </description>
</property>

-- Hadoop namenode configuration

Also, we should setup here address of LocalKMS, located on NameNode
core-site.xml:
<property>
    <name>dfs.encryption.key.provider.uri</name>
    <value>kms://http@localhost:16000/kms</value>
</property>
<property>
<name>hadoop.security.key.provider.path</name>
  <value>kms://http@localhost:16000/kms</value>
  <description>
    The KeyProvider to use when interacting with encryption keys used
    when reading and writing to an encryption zone.
  </description>
</property>
