if [[ $# -ne 1 ]];then
	echo "nucypher kms install required global kms url"
	exit 1
fi

GLOBAL_KMS_ADDR=$1

PWD=`pwd`
echo "current working dir : $PWD"
## install props 
NUCYPHER_PACKAGE=nucypher_aws-0.1
DOWNLOAD_DIR=aws_package

NUCYPHER_DIRNAME=nucypher-kms
NUCYPHER_HOME_DIR=/usr/lib/$NUCYPHER_DIRNAME
NUCYPHER_HOME_DIR_CONF_LINK=$NUCYPHER_HOME_DIR/etc
NUCYPHER_SBIN_DIR=$NUCYPHER_HOME_DIR/sbin
NUCYPHER_LIBEXEC_DIR=$NUCYPHER_HOME_DIR/libexec
NUCYPHER_SHARE_DIR=$NUCYPHER_HOME_DIR/share
NUCYPHER_ETC_CONF_DIR=/etc/$NUCYPHER_DIRNAME/conf
NUCYPHER_LOG_DIR=/var/log/$NUCYPHER_DIRNAME
NUCYPHER_KEY_ROTATION_DIR=/home/hadoop

# download nucypher package
DOWNLOAD_URL=https://s3-eu-west-1.amazonaws.com/nucypher/aws
wget $DOWNLOAD_URL/$NUCYPHER_PACKAGE.tar.gz
if [[ $? -ne 0  ]];then
        echo "Error in nucypher package download step from url : $DOWNLOAD_URL/$NUCYPHER_PACKAGE.tar.gz"
        exit 1
fi
gunzip $NUCYPHER_PACKAGE.tar.gz 
tar -xvf $NUCYPHER_PACKAGE.tar 
rm -f $NUCYPHER_PACKAGE.tar

echo "creating nucypher install target"
# create kms deploy structure
sudo mkdir -p $NUCYPHER_HOME_DIR_CONF_LINK
sudo mkdir -p $NUCYPHER_LIBEXEC_DIR
sudo mkdir -p $NUCYPHER_SBIN_DIR
sudo mkdir -p $NUCYPHER_SHARE_DIR
sudo mkdir -p $NUCYPHER_ETC_CONF_DIR
sudo mkdir -p $NUCYPHER_LOG_DIR

# depending on the node profile install transformation node or local kms
IS_MASTER=$(grep isMaster /mnt/var/lib/info/instance.json | grep true | wc -l)
if [[ $IS_MASTER -eq 1 ]];then
	echo "install REN"
	sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-env.ren.sh $NUCYPHER_ETC_CONF_DIR/kms-env.sh
	if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-env.ren.sh to $NUCYPHER_ETC_CONF_DIR/kms-env.sh"
        exit 1
	fi
	sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-log4j.ren.properties $NUCYPHER_ETC_CONF_DIR/kms-log4j.properties
	if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-log4j.ren.properties to $NUCYPHER_ETC_CONF_DIR/kms-log4j.properties"
        exit 1
	fi
	sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-site.ren.xml $NUCYPHER_ETC_CONF_DIR/kms-site.xml
	if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-site.ren.xml to $NUCYPHER_ETC_CONF_DIR/kms-site.xml"
        exit 1
	fi
else 
	echo "install Local kms"
	REN_ADDR=$(less /mnt/var/lib/info/job-flow-state.txt | grep -A1 yarn.resourcemanager.hostname | grep value | head -1 | cut -d: -f2 | cut -d\" -f2)
	if [[ $? -ne 0  ]];then
        echo "Error can't read master node address"
        exit 1
	fi
	echo "using zero ren addr : $REN_ADDR"
	sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-env.local-kms.sh $NUCYPHER_ETC_CONF_DIR/kms-env.sh
	if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-env.local-kms.sh to $NUCYPHER_ETC_CONF_DIR/kms-env.sh"
        exit 1
	fi
	sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-log4j.local-kms.properties $NUCYPHER_ETC_CONF_DIR/kms-log4j.properties
	if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-log4j.local-kms.properties to $NUCYPHER_ETC_CONF_DIR/kms-log4j.properties"
        exit 1
	fi
	sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-site.local-kms.xml $NUCYPHER_ETC_CONF_DIR/kms-site.xml
	if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-site.local-kms.xml to $NUCYPHER_ETC_CONF_DIR/kms-site.xml"
        exit 1
	fi
	sudo sed -i "s/<value>ren:\/\/http@localhost:16000\/kms<\/value>/<value>ren:\/\/http@${REN_ADDR}:16110\/kms<\/value>/" $NUCYPHER_ETC_CONF_DIR/kms-site.xml
	if [[ $? -ne 0  ]];then
        echo "Error can't edit REN provideruri in $NUCYPHER_ETC_CONF_DIR/kms-site.xml"
        exit 1
	fi
fi

# set gloabl kms in kms-site.xml
sudo sed -i "s/<value>prekms:\/\/http@localhost:16000\/kms<\/value>/<value>prekms:\/\/http@${GLOBAL_KMS_ADDR}:16000\/kms<\/value>/" $NUCYPHER_ETC_CONF_DIR/kms-site.xml
if [[ $? -ne 0  ]];then
    echo "Error can't edit global kms provider uri in $NUCYPHER_ETC_CONF_DIR/kms-site.xml"
    exit 1
fi

# link hadoop conf 
sudo ln -s /etc/hadoop/conf/core-site.xml $NUCYPHER_ETC_CONF_DIR/core-site.xml
if [[ $? -ne 0  ]];then
	echo "Error can't link : /etc/hadoop/conf/core-site.xml in $NUCYPHER_ETC_CONF_DIR/core-site.xml"
	exit 1
fi
sudo ln -s /etc/hadoop/conf/hdfs-site.xml $NUCYPHER_ETC_CONF_DIR/hdfs-site.xml

# deploy remaining artifacts
sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-acls.xml $NUCYPHER_ETC_CONF_DIR
if [[ $? -ne 0  ]];then
	echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-acls.xml to $NUCYPHER_ETC_CONF_DIR"
	exit 1
fi
sudo cp -r $DOWNLOAD_DIR/share/* $NUCYPHER_SHARE_DIR
if [[ $? -ne 0  ]];then
	echo "Error can't copy : $DOWNLOAD_DIR/share/* to $NUCYPHER_SHARE_DIR"
	exit 1
fi
sudo cp $DOWNLOAD_DIR/sbin/kms.sh $NUCYPHER_SBIN_DIR
if [[ $? -ne 0  ]];then
	echo "Error can't copy : $DOWNLOAD_DIR/sbin/kms.sh to $NUCYPHER_SBIN_DIR"
	exit 1
fi
sudo ln -s $NUCYPHER_ETC_CONF_DIR/ $NUCYPHER_HOME_DIR_CONF_LINK/hadoop
sudo cp $DOWNLOAD_DIR/libexec/* $NUCYPHER_LIBEXEC_DIR/
if [[ $? -ne 0  ]];then
	echo "Error can't copy : $DOWNLOAD_DIR/libexec/* to $NUCYPHER_LIBEXEC_DIR/"
	exit 1
fi

echo "deploy completed successfully"




