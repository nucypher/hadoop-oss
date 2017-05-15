#!/usr/bin/env bash

display_usage() {
	echo "This script runs nucypher-hadoop key rotation."
	echo -e "\nUsage:\n$0 ZONEPATH1,ZONEPATH2,...,ZONEPATHN [GLOBAL_KMS_ADDRESS:GLOBAL_KMS_PORT]\n"
	}

if [  $# -le 1 ]
then
    display_usage
    exit 1
fi

if [[ ( $# == "--help") ||  $# == "-h" ]]
then
    display_usage
    exit 0
fi

ZDB_KR_LIBS=/opt/nucypher-kms/share/hadoop/kms/tomcat/webapps/kms/WEB-INF/lib

hadoop jar $ZDB_KR_LIBS/nucypher-keyrotation-0.0.1-SNAPSHOT.jar \
	com.nucypher.prkeyrotation.Client \
	$1 \
	$ZDB_KR_LIBS/nucypher-keyrotation-0.0.1-SNAPSHOT.jar,$ZDB_KR_LIBS/nucypher-crypto-0.0.1-SNAPSHOT.jar,$ZDB_KR_LIBS/bcprov-jdk15on-1.54.jar,$ZDB_KR_LIBS/nucypher-hadoop-plugins-0.0.1-SNAPSHOT.jar \
	$2