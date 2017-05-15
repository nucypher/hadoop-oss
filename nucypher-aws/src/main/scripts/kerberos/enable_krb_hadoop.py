import xml.etree.ElementTree as et
import xml.dom.minidom as md

core_site = '/etc/hadoop/conf/core-site.xml'
hdfs_site = '/etc/hadoop/conf/hdfs-site.xml'
yarn_site = '/etc/hadoop/conf/yarn-site.xml'
mapred_site = '/etc/hadoop/conf/mapred-site.xml'
kms_site = '/etc/hadoop-kms/conf/kms-site.xml'
ssl_server = '/etc/hadoop-kms/conf/ssl-server.xml'
ssl_client = '/etc/hadoop-kms/conf/ssl-client.xml'

def pretty_print(file_name):
    t = md.parse(file_name)
    str_ = t.toprettyxml(newl='\n', indent='\t')
    with open(file_name, 'w') as f:
        f.write(str_)


def update_xml_config(file_name, prop_name, prop_value):
    tree = et.parse(file_name)
    root = tree.getroot()
    for config in root.iter('property'):
        name = config.find('name').text
        if name == prop_name:
            config.find('value').text = prop_value
            tree.write(file_name)
            break


def add_xml_config(file_name, prop_name, prop_value):
    tree = et.parse(file_name)
    root = tree.getroot()
    prop_node = et.SubElement(root, 'property', )
    prop_name_node = et.SubElement(prop_node, 'name')
    prop_name_node.text = prop_name
    prop_val_node = et.SubElement(prop_node, 'value')
    prop_val_node.text = prop_value
    tree.write(file_name)


# core site
update_xml_config(core_site, 'hadoop.security.authentication', 'kerberos')
add_xml_config(core_site, 'hadoop.security.authorization', 'true')
# hdfs site
add_xml_config(hdfs_site, 'dfs.block.access.token.enable', 'true')
add_xml_config(hdfs_site, 'dfs.namenode.kerberos.principal', 'hdfs/_HOST@ZERODB.LOCAL')
add_xml_config(hdfs_site, 'dfs.namenode.keytab.file', '/etc/hadoop/conf/hdfs.keytab')
add_xml_config(hdfs_site, 'dfs.namenode.kerberos.internal.spnego.principal', 'HTTP/_HOST@ZERODB.LOCAL')
add_xml_config(hdfs_site, 'dfs.secondary.namenode.keytab.file', '/etc/hadoop/conf/hdfs.keytab')
add_xml_config(hdfs_site, 'dfs.secondary.namenode.kerberos.principal', 'hdfs/_HOST@ZERODB.LOCAL')
add_xml_config(hdfs_site, 'dfs.secondary.namenode.kerberos.internal.spnego.principal', 'HTTP/_HOST@ZERODB.LOCAL')
add_xml_config(hdfs_site, 'dfs.datanode.data.dir.perm', '700')
add_xml_config(hdfs_site, 'dfs.datanode.address', '0.0.0.0:1004')
add_xml_config(hdfs_site, 'dfs.datanode.http.address', '0.0.0.0:1006')
add_xml_config(hdfs_site, 'dfs.datanode.keytab.file', '/etc/hadoop/conf/hdfs.keytab')
add_xml_config(hdfs_site, 'dfs.datanode.kerberos.principal', 'hdfs/_HOST@ZERODB.LOCAL')
add_xml_config(hdfs_site, 'dfs.web.authentication.kerberos.principal', 'HTTP/_HOST@ZERODB.LOCAL')
add_xml_config(hdfs_site, 'dfs.http.policy', 'HTTPS_ONLY')
# yarn site
add_xml_config(yarn_site, 'yarn.resourcemanager.keytab', '/etc/hadoop/conf/yarn.keytab')
add_xml_config(yarn_site, 'yarn.resourcemanager.principal', 'yarn/_HOST@ZERODB.LOCAL')
add_xml_config(yarn_site, 'yarn.nodemanager.keytab', '/etc/hadoop/conf/yarn.keytab')
add_xml_config(yarn_site, 'yarn.nodemanager.principal', 'yarn/_HOST@ZERODB.LOCAL')
add_xml_config(yarn_site, 'yarn.nodemanager.container-executor.class',
               'org.apache.hadoop.yarn.server.nodemanager.LinuxContainerExecutor')
add_xml_config(yarn_site, 'yarn.nodemanager.linux-container-executor.group', 'hadoop')
add_xml_config(yarn_site, 'yarn.http.policy', 'HTTPS_ONLY')
# mapred site
add_xml_config(mapred_site, 'mapreduce.jobhistory.keytab', '/etc/hadoop/conf/mapred.keytab')
add_xml_config(mapred_site, 'mapreduce.jobhistory.principal', 'mapred/_HOST@ZERODB.LOCAL')
# kms site
update_xml_config(kms_site, 'hadoop.kms.authentication.type', 'kerberos')
add_xml_config(mapred_site, 'hadoop.kms.authentication.kerberos.keytab', '/etc/hadoop-kms/conf/http.keytab')
add_xml_config(mapred_site, 'hadoop.kms.authentication.kerberos.principal', 'HTTP/localhost')
add_xml_config(mapred_site, 'hadoop.kms.authentication.kerberos.name.rules', 'DEFAULT')
# ssl server
add_xml_config(mapred_site, 'ssl.server.keystore.type', 'jks')
add_xml_config(mapred_site, 'ssl.server.keystore.password', 'password')
add_xml_config(mapred_site, 'ssl.server.keystore.keypassword', 'password')
add_xml_config(mapred_site, 'ssl.server.keystore.location', '/etc/hadoop/conf/hadoop-private-keystore.jks')
add_xml_config(mapred_site, 'ssl.server.truststore.type', 'jks')
add_xml_config(mapred_site, 'ssl.server.truststore.location', '/etc/hadoop/conf/hadoop_certs')
add_xml_config(mapred_site, 'ssl.server.truststore.password', 'changeit')
# ssl client
add_xml_config(mapred_site, 'ssl.client.keystore.location', '/etc/hadoop/conf/hadoop_certs')
add_xml_config(mapred_site, 'ssl.client.keystore.password', 'changeit')
add_xml_config(mapred_site, 'ssl.client.truststore.type', 'jks')
add_xml_config(mapred_site, 'ssl.client.truststore.password', 'changeit')
add_xml_config(mapred_site, 'ssl.client.truststore.location', '/etc/hadoop/conf/hadoop_certs')
# pretty print
pretty_print(core_site)
pretty_print(mapred_site)
pretty_print(hdfs_site)
pretty_print(yarn_site)
pretty_print(kms_site)
pretty_print(kms_server)
pretty_print(kms_client)
