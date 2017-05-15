
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
sudo -rm -r $NUCYPHER_HOME_DIR
sudo -rm -r $NUCYPHER_ETC_CONF_DIR
sudo mkdir -p $NUCYPHER_HOME_DIR_CONF_LINK
sudo mkdir -p $NUCYPHER_LIBEXEC_DIR
sudo mkdir -p $NUCYPHER_SBIN_DIR
sudo mkdir -p $NUCYPHER_SHARE_DIR
sudo mkdir -p $NUCYPHER_ETC_CONF_DIR
sudo mkdir -p $NUCYPHER_LOG_DIR

# copy kms config files
sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-env.sh /etc/nucypher-kms/conf/kms-env.sh
if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-env.sh to $NUCYPHER_ETC_CONF_DIR/kms-env.sh"
        exit 1
fi
sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-log4j.properties /etc/nucypher-kms/conf/kms-log4j.properties
if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-log4j.properties to $NUCYPHER_ETC_CONF_DIR/kms-log4j.properties"
        exit 1
fi
sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-site.xml /etc/nucypher-kms/conf/kms-site.xml
if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-site.xml to $NUCYPHER_ETC_CONF_DIR/kms-site.xml"
        exit 1
fi
sudo cp $DOWNLOAD_DIR/etc/hadoop/kms-acls.xml /etc/nucypher-kms/conf
if [[ $? -ne 0  ]];then
        echo "Error can't copy : $DOWNLOAD_DIR/etc/hadoop/kms-acls.xml to $NUCYPHER_ETC_CONF_DIR/kms-site.xml"
        exit 1
fi
# deploy remaining artifacts
sudo cp -r $DOWNLOAD_DIR/share/* /usr/lib/nucypher-kms/share/
if [[ $? -ne 0  ]];then
  echo "Error can't copy : $DOWNLOAD_DIR/share/* to $NUCYPHER_SHARE_DIR"
  exit 1
fi
sudo cp $DOWNLOAD_DIR/sbin/kms.sh /usr/lib/nucypher-kms/sbin/
if [[ $? -ne 0  ]];then
  echo "Error can't copy : $DOWNLOAD_DIR/sbin/kms.sh to $NUCYPHER_SBIN_DIR"
  exit 1
fi
sudo ln -s /etc/nucypher-kms/conf/ /usr/lib/nucypher-kms/etc/hadoop
sudo cp $DOWNLOAD_DIR/libexec/* /usr/lib/nucypher-kms/libexec/
if [[ $? -ne 0  ]];then
  echo "Error can't copy : $DOWNLOAD_DIR/libexec/* to $NUCYPHER_LIBEXEC_DIR/"
  exit 1
fi
# generate key store password file
echo abcdef > kms.keystore.password
sudo cp kms.keystore.password $NUCYPHER_SHARE_DIR/hadoop/kms/tomcat/webapps/kms/WEB-INF/classes/
if [[ $? -ne 0  ]];then
  echo "Error can't create kms keystore password file "
  exit 1
fi
sudo rm -f kms.keystore.password
#
sudo echo "
<configuration>

  <property>
    <name>hadoop.security.authentication</name>
    <value>simple</value>
  </property>

  <property>
    <name>hadoop.security.key.default.bitlength</name>
    <value>128</value>
  </property>
</configuration>
" > core-site.xml 
sudo cp core-site.xml $NUCYPHER_ETC_CONF_DIR/
sudo rm -f core-site.xml
#
sudo rm -f $NUCYPHER_SHARE_DIR/hadoop/kms/tomcat/webapps/kms/WEB-INF/lib/._*.jar
echo "###########################################"
echo "nucypher global kms installation successful"
echo "###########################################"
