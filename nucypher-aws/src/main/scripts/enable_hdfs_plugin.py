import xml.etree.ElementTree as et
import sys

file_xml = sys.argv[1]
#plugin_uri = sys.argv[2]


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


update_xml_config(file_xml, 'dfs.namenode.plugins', 'com.nucypher.hadoop.hdfs.plugin.NuCypherExtServicePlugin')

#add_xml_config(file_xml, 'nucypher.ext.servicerpc-address', plugin_uri)
