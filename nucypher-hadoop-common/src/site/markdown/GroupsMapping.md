<!---
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License. See accompanying LICENSE file.
-->

Hadoop Groups Mapping
===================

* [Hadoop Groups Mapping](#Hadoop_Groups_Mapping)
    * [Overview](#Overview)
    * [LDAP Groups Mapping](#LDAP_Groups_Mapping)
        * [Active Directory](#Active_Directory)
        * [POSIX Groups](#POSIX_Groups)
        * [SSL](#SSL)
    * [Composite Groups Mapping](#Composite_Groups_Mapping)
        * [Multiple group mapping providers configuration sample](#Multiple_group_mapping_providers_configuration_sample)

Overview
--------
The groups of a user is determined by a group mapping service provider.
Hadoop supports various group mapping mechanisms, configured by the `hadoop.security.group.mapping` property. Some of them, such as `JniBasedUnixGroupsMappingWithFallback`, use operating
systems' group name resolution and requires no configuration. But Hadoop also supports special group mapping mechanisms through
LDAP and composition of LDAP and operating system group name resolution, which require additional configurations.
`hadoop.security.group.mapping` can be one of the following:

*    **org.apache.hadoop.security.JniBasedUnixGroupsMappingWithFallback**

     The default implementation. It will determine if the Java Native Interface (JNI) is available. If JNI is available, the implementation will use the API within hadoop to resolve a list of groups for a user. If JNI is not available then the shell-based implementation, `ShellBasedUnixGroupsMapping`, is used.

*    **org.apache.hadoop.security.JniBasedUnixGroupsNetgroupMappingWithFallback**

     Similar to `JniBasedUnixGroupsMappingWithFallback`. If JNI is available, it obtains netgroup membership using the Hadoop native API; otherwise uses `ShellBasedUnixGroupsNetgroupMapping`.

*    **org.apache.hadoop.security.ShellBasedUnixGroupsMapping**

     This implementation shells out with the `bash -c groups` command (for a Linux/Unix environment) or the `net group` command (for a Windows environment) to resolve a list of groups for a user.

*    **org.apache.hadoop.security.ShellBasedUnixGroupsNetgroupMapping**

     This implementation is similar to `ShellBasedUnixGroupsMapping`, except that it executes `getent netgroup` command to get netgroup membership.

*    **org.apache.hadoop.security.LdapGroupsMapping**

     An alternate implementation, which connects directly to an LDAP server to resolve the list of groups. However, this provider should only be used if the required groups reside exclusively in LDAP, and are not materialized on the Unix servers.
     LdapGroupsMapping supports SSL connection and POSIX group semantics. See section [LDAP Groups Mapping](#LDAP_Groups_Mapping) for details.

*    **org.apache.hadoop.security.CompositeGroupsMapping**

     This implementation composites other group mapping providers for determining group membership. This allows to combine existing provider implementations and composite a virtually new provider without customized development to deal with complex situation. See section [Composite Groups Mapping](#Composite_Groups_Mapping) for details.

For HDFS, the mapping of users to groups is performed on the NameNode. Thus, the host system configuration of the NameNode determines the group mappings for the users.

Note that HDFS stores the user and group of a file or directory as strings; there is no conversion from user and group identity numbers as is conventional in Unix.


LDAP Groups Mapping
--------
This provider supports LDAP with simple password authentication using JNDI API.
`hadoop.security.group.mapping.ldap.url` must be set. This refers to the URL of the LDAP server for resolving user groups.

`hadoop.security.group.mapping.ldap.base` configures the search base for the LDAP connection. This is a distinguished name, and will typically be the root of the LDAP directory.

If the LDAP server does not support anonymous binds,
set the distinguished name of the user to bind in `hadoop.security.group.mapping.ldap.bind.user`.
The path to the file containing the bind user's password is specified in `hadoop.security.group.mapping.ldap.bind.password.file`.
This file should be readable only by the Unix user running the daemons.

It is possible to set a maximum time limit when searching and awaiting a result.
Set `hadoop.security.group.mapping.ldap.directory.search.timeout` to 0 if infinite wait period is desired. Default is 10,000 milliseconds (10 seconds).

The implementation does not attempt to resolve group hierarchies. Therefore, a user must be an explicit member of a group object
in order to be considered a member.


### Active Directory ###
The default configuration supports LDAP group name resolution with an Active Directory server.

### POSIX Groups ###
If the LDAP server supports POSIX group semantics, Hadoop can perform LDAP group resolution queries to the server by setting both
`hadoop.security.group.mapping.ldap.search.filter.user` to  `posixAccount` and
`hadoop.security.group.mapping.ldap.search.filter.group` to `posixGroup`.

### SSL ###
To secure the connection, the implementation supports LDAP over SSL (LDAPS). SSL is enable by setting `hadoop.security.group.mapping.ldap.ssl` to `true`.
In addition, specify the path to the keystore file for SSL connection in `hadoop.security.group.mapping.ldap.ssl.keystore` and keystore password in `hadoop.security.group.mapping.ldap.ssl.keystore.password`.
Alternatively, store the keystore password in a file, and point `hadoop.security.group.mapping.ldap.ssl.keystore.password.file` to that file. For security purposes, this file should be readable only by the Unix user running the daemons.

Composite Groups Mapping
--------
`CompositeGroupsMapping` works by enumerating a list of service providers in `hadoop.security.group.mapping.providers`.
It get groups from each of the providers in the list one after the other. If `hadoop.security.group.mapping.providers.combined` is `true`, merge the groups returned by all providers; otherwise, return the groups in the first successful provider.
See the following section for a sample configuration.

### Multiple group mapping providers configuration sample ###
  This sample illustrates a typical use case for `CompositeGroupsMapping` where
Hadoop authentication uses MIT Kerberos which trusts an AD realm. In this case, service
principals such as hdfs, mapred, hbase, hive, oozie and etc can be placed in MIT Kerberos,
but end users are just from the trusted AD. For the service principals, `ShellBasedUnixGroupsMapping`
provider can be used to query their groups for efficiency, and for end users, `LdapGroupsMapping`
provider can be used. This avoids to add group entries in AD for service principals when only using
`LdapGroupsMapping` provider.
  In case multiple ADs are involved and trusted by the MIT Kerberos, `LdapGroupsMapping`
provider can be used multiple times with different AD specific configurations. This sample also shows how
to do that. Here are the necessary configurations.

```<property>
  <name>hadoop.security.group.mapping</name>
  <value>org.apache.hadoop.security.CompositeGroupsMapping</value>
  <description>
    Class for user to group mapping (get groups for a given user) for ACL, which
    makes use of other multiple providers to provide the service.
  </description>
</property>

<property>
  <name>hadoop.security.group.mapping.providers</name>
  <value>shell4services,ad4usersX,ad4usersY</value>
  <description>
    Comma separated of names of other providers to provide user to group mapping.
  </description>
</property>

<property>
  <name>hadoop.security.group.mapping.providers.combined</name>
  <value>true</value>
  <description>
    true or false to indicate whether groups from the providers are combined or not. The default value is true
    If true, then all the providers will be tried to get groups and all the groups are combined to return as
    the final results. Otherwise, providers are tried one by one in the configured list order, and if any
    groups are retrieved from any provider, then the groups will be returned without trying the left ones.
  </description>
</property>

<property>
  <name>hadoop.security.group.mapping.provider.shell4services</name>
  <value>org.apache.hadoop.security.ShellBasedUnixGroupsMapping</value>
  <description>
    Class for group mapping provider named by 'shell4services'. The name can then be referenced
    by hadoop.security.group.mapping.providers property.
  </description>
</property>

<property>
  <name>hadoop.security.group.mapping.provider.ad4usersX</name>
  <value>org.apache.hadoop.security.LdapGroupsMapping</value>
  <description>
    Class for group mapping provider named by 'ad4usersX'. The name can then be referenced
    by hadoop.security.group.mapping.providers property.
  </description>
</property>

<property>
  <name>hadoop.security.group.mapping.provider.ad4usersY</name>
  <value>org.apache.hadoop.security.LdapGroupsMapping</value>
  <description>
    Class for group mapping provider named by 'ad4usersY'. The name can then be referenced
    by hadoop.security.group.mapping.providers property.
  </description>
</property>

<property>
<name>hadoop.security.group.mapping.provider.ad4usersX.ldap.url</name>
<value>ldap://ad-host-for-users-X:389</value>
  <description>
    ldap url for the provider named by 'ad4usersX'. Note this property comes from
    'hadoop.security.group.mapping.ldap.url'.
  </description>
</property>

<property>
<name>hadoop.security.group.mapping.provider.ad4usersY.ldap.url</name>
<value>ldap://ad-host-for-users-Y:389</value>
  <description>
    ldap url for the provider named by 'ad4usersY'. Note this property comes from
    'hadoop.security.group.mapping.ldap.url'.
  </description>
</property>
```

You also need to configure other properties like
  hadoop.security.group.mapping.ldap.bind.password.file and etc.
for ldap providers in the same way as above does.
