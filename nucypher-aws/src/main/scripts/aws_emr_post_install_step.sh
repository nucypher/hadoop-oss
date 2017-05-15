#if [[ $# -ne 1 ]];then
#	echo "nucypher kms aws step needs one arg : cluster identity file name "
#	exit 1
#fi
# ssh id to be changed to the actual id used to create the cluster
CLUSTER_ID=aws_ych.pem
# nucypher package location
DOWNLOAD_URL=https://s3-eu-west-1.amazonaws.com/nucypher/aws
NUCYPHER_DIRNAME=nucypher-kms
NUCYPHER_HOME_DIR=/usr/lib/$NUCYPHER_DIRNAME
NUCYPHER_SBIN_DIR=$NUCYPHER_HOME_DIR/sbin
NUCYPHER_KEY_ROTATION_DIR=/home/hadoop

# start nucypher kms
IS_MASTER=$(grep isMaster /mnt/var/lib/info/instance.json | grep true | wc -l)

if [[ $IS_MASTER -eq 1 ]];then
	echo "stoping hadoop kms on namenode" 
	sudo /sbin/stop hadoop-kms
	if [[ $? -ne 0  ]];then
		echo "Error can't stop hadoop kms daemon"
		exit 1
	fi
	echo "starting nucypher REN kms on namenode"
	sudo $NUCYPHER_SBIN_DIR/kms.sh start
	if [[ $? -ne 0  ]];then
		echo "Error can't start nucypher-kms REN daemon"
		exit 1
	fi
else
	echo "error node is not a master node" 
	exit 1
fi

## add ssh id to master
wget $DOWNLOAD_URL/$CLUSTER_ID
if [[ $? -ne 0  ]];then
	echo "Error can't get cluster identity file"
	exit 1
fi
chmod 700 $CLUSTER_ID
# hdfs plugin uri
MASTER_NODE=$(less /mnt/var/lib/info/job-flow-state.txt | grep -A1 yarn.resourcemanager.hostname | grep value | head -1 | cut -d: -f2 | cut -d\" -f2)
NUCYPHER_PLUGIN_URI=${MASTER_NODE}:8125
# build remote script 
# start local kms and set plugin uri in yarn conf
echo "sudo $NUCYPHER_SBIN_DIR/kms.sh start" > data_node_aws_step.sh
echo "sudo sed -i \"s/_NUCYPHER_PLUGIN_URI_/${NUCYPHER_PLUGIN_URI}:8125/\" /etc/hadoop/conf/yarn-site.xml" >> data_node_aws_step.sh
# build data nodes file
hdfs dfsadmin -report | grep ^Name | cut -f2 -d: | cut -f2 -d' ' > datanodes.txt
if [[ $? -ne 0  ]];then
	echo "Error can't create datanodes files"
	exit 1
fi
# run remote script on all nodes
while read line;do
	echo "starting nucypher local kms on data node : $line" 
	ssh -o StrictHostKeyChecking=no -i $CLUSTER_ID hadoop@$line 'bash -s' < data_node_aws_step.sh
	if [[ $? -ne 0  ]];then
		echo "Error can't start local kms on $line "
		exit 1
	fi
done <datanodes.txt

# point core-site and hdfs-site in master node to local kms of one of the datanodes. 
data_node_var=$(cat datanodes.txt| head -1)
sudo sed -i "s/<value>kms:\/\/http@localhost:16010\/kms<\/value>/<value>kms:\/\/http@${data_node_var}:16010\/kms<\/value>/" /etc/hadoop/conf/hdfs-site.xml
if [[ $? -ne 0  ]];then
	echo "Error can't edit hdfs-site on master node "
	exit 1
fi
sudo sed -i "s/<value>kms:\/\/http@localhost:16010\/kms<\/value>/<value>kms:\/\/http@${data_node_var}:16010\/kms<\/value>/" /etc/hadoop/conf/core-site.xml
if [[ $? -ne 0  ]];then
	echo "Error can't edit core-site on master node "
	exit 1
fi

# install key rotation on master node
wget $DOWNLOAD_URL/keyrotation.tar.gz
gunzip keyrotation.tar.gz 
tar -xvf keyrotation.tar 
rm -f keyrotation.tar
cp -r keyrotation $NUCYPHER_KEY_ROTATION_DIR
chmod 755 $NUCYPHER_KEY_ROTATION_DIR/keyrotation/run_rotation.sh 
# enable plugin
sudo sed -i "s/_NUCYPHER_PLUGIN_URI_/${NUCYPHER_PLUGIN_URI}/" /etc/hadoop/conf/yarn-site.xml
wget $DOWNLOAD_URL/enable_hdfs_plugin.py
chmod 755 enable_hdfs_plugin.py
sudo python enable_hdfs_plugin.py /etc/hadoop/conf/hdfs-site.xml 
# add nucypher plugin to namenode classpath
sudo cp $NUCYPHER_KEY_ROTATION_DIR/keyrotation/libs/nucypher-hadoop-plugins-0.0.1-SNAPSHOT.jar /usr/lib/hadoop-hdfs/lib/

# restart namenode
sudo /sbin/stop hadoop-hdfs-namenode
if [[ $? -ne 0  ]];then
	echo "Error can't stop namenode "
	exit 1
fi
sleep 3
sudo /sbin/start hadoop-hdfs-namenode
if [[ $? -ne 0  ]];then
	echo "Error can't start namenode "
	exit 1
fi

# restart yanr rm
sudo /sbin/stop hadoop-yarn-resourcemanager
if [[ $? -ne 0  ]];then
	echo "Error can't stop yarn resourcemanager "
	exit 1
fi
sleep 3
sudo /sbin/start hadoop-yarn-resourcemanager
if [[ $? -ne 0  ]];then
	echo "Error can't start yarn resourcemanager "
	exit 1
fi

