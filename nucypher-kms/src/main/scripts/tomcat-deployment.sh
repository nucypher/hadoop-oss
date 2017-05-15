#!/bin/bash

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.kms

# This script must be sourced so that it can set CATALINA_BASE for the parent process

TOMCAT_CONF=${TOMCAT_CONF:-`readlink -e /etc/hadoop-kms/tomcat-conf`}
TOMCAT_DEPLOYMENT=${TOMCAT_DEPLOYMENT:-/var/lib/hadoop-kms/tomcat-deployment}
KMS_HOME=${KMS_HOME:-/usr/lib/hadoop-kms}

function copy_and_resolve() {
    source_dir=${1}
    target_dir=${2}

    # Some directories contain both configuration and binaries, so we have to copy the contents individually
    mkdir -p ${target_dir}
    cp -r ${source_dir}/* ${target_dir}

    for source_symlink in `find ${source_dir} -type l`; do
        # This is relative to the source specifically, so that relative symlinks are consistent
        symlink_location=${source_symlink/${source_dir}/}
        symlink_target=`readlink -e ${source_symlink}`
        if [ -n "${symlink_target}" ]; then
            rm -f ${target_dir}${symlink_location}
            cp -r ${symlink_target} ${target_dir}${symlink_location}
        fi
    done
}

rm -rf ${TOMCAT_DEPLOYMENT}
mkdir ${TOMCAT_DEPLOYMENT}
#copy_and_resolve ${TOMCAT_CONF}/conf    ${TOMCAT_DEPLOYMENT}/conf
copy_and_resolve ${KMS_HOME}/share/hadoop/kms/tomcat ${TOMCAT_DEPLOYMENT}

#if [ -n "${BIGTOP_CLASSPATH}" ] ; then
#  sed -i -e "s#^\(common.loader=.*\)\$#\1,${BIGTOP_CLASSPATH/:/,}#" ${TOMCAT_DEPLOYMENT}/conf/catalina.properties
#fi

# Copying in all the jars from the plugin directory to lib.
if [ -n "${KMS_PLUGIN_DIR}" ] && [ -d "${KMS_PLUGIN_DIR}" ] ; then
  yes n | cp -r -i $KMS_PLUGIN_DIR/*.jar ${TOMCAT_DEPLOYMENT}/webapps/kms/WEB-INF/lib
fi

chown -R kms:kms ${TOMCAT_DEPLOYMENT}
chmod -R 755 ${TOMCAT_DEPLOYMENT}

export CATALINA_BASE=${TOMCAT_DEPLOYMENT}

# check if the ssl file is present and set the URL to monitor accordingly
if [ -f ${TOMCAT_DEPLOYMENT}/conf/ssl-server.xml.conf ]; then
  echo "export WATCHDOG_MONITOR_URL=https://localhost:16000/kms" > ${TOMCAT_DEPLOYMENT}/conf/watchdog.properties
else
  echo "export WATCHDOG_MONITOR_URL=http://localhost:16000/kms" > ${TOMCAT_DEPLOYMENT}/conf/watchdog.properties
fi


