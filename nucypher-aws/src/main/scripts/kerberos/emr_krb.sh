
download_url=https://s3-eu-west-1.amazonaws.com/yacineawsireland/zerodb_aws
root_krb=krb
ssh_id=aws_ych.pem
# generated files
data_node_file=datanodes.txt
hadoop_hosts_file=hadoop_hosts.txt
remote_cmd=remote_cmd.sh
trust_store=/etc/hadoop/conf/hadoop_certs
#  aws emr master services list
master_srvs=(hadoop-hdfs-namenode hadoop-yarn-resourcemanager hadoop-httpfs hadoop-mapreduce-historyserver hadoop-yarn-proxyserver hadoop-kms)
# aws emr java security lib location
java_lib_security_dir=/usr/lib/jvm/jre-1.8.0-openjdk.x86_64/lib/security/
# kdc admin access
kdc_admin_principal=root/admin@ZERODB.LOCAL
kdc_admin_pass=yacine

ops_master_srv(){
echo "$1ing master services"
# ops master services
for srv in ${master_srvs[*]};do
	sudo /sbin/$1 $srv
	if [[ $? -ne 0  ]];then
		echo "Error can't stop $srv "
	fi
done
}

run_remote_cmd(){
while read host;do
	echo "exec $1 on : $host" 
	ssh -o StrictHostKeyChecking=no -i $ssh_id hadoop@$host 'bash -s' < $1
	if [[ $? -ne 0  ]];then
		echo "Error can't local srv on $line "
	fi
done <$2
}

ops_node_srv(){
echo "$1ing node services"
# ops node services
echo "building remote cmd script : $remote_cmd"
echo "
node_srvs=(hadoop-hdfs-datanode hadoop-yarn-nodemanager)
for srv in \${node_srvs[*]};do
	sudo /sbin/$1 \$srv
	if [[ \$? -ne 0  ]];then
		echo \"Error can't stop $srv \"
	fi
done
" > $remote_cmd
echo "running remote cmd script using $data_node_file"
run_remote_cmd $remote_cmd $data_node_file

}

function gen_hadoop_hosts(){
> $hadoop_hosts_file
while read host;do
	h=$(nslookup $host | grep = | awk -F"=" '{print $2;}' | xargs)
	echo ${h::-1} >> $hadoop_hosts_file
done <$data_node_file
m=$(hostname -f)
echo $m >> $hadoop_hosts_file
}

function gen_ssl_certs() {
sudo rm -f /etc/pki/CA/index.txt
sudo touch /etc/pki/CA/index.txt
sudo echo '1000' > /etc/pki/CA/serial
if [[ ! -f $hadoop_hosts_file ]];then
	echo "hadoop hosts file missing. It will be generated..."
	gen_hadoop_hosts
fi
readarray hadoop_hosts < $hadoop_hosts_file
#echo ${hadoop_hosts[*]}
# 1. CA SSL certificate
if [ ! -e "ca.crt" ]; then
    sudo openssl genrsa -out ca.key 2048
    sudo openssl req -new -x509 -days 1826 -key ca.key -out ca.crt -subj "/C=UK/ST=London/L=London City/O=ZeroDB/OU=Hadoop/CN=ZeroDBCA"
fi
# 2. Server SSL certificates
for host in ${hadoop_hosts[@]}; do
	if [  -e "${host}.crt" ]; then break; fi
	sudo openssl req -new -newkey rsa:2048 -nodes -keyout "${host}.key" -out "${host}.csr"  -subj "/C=UK/ST=London/L=London City/O=ZeroDB/OU=Hadoop/CN=$host"
	sudo openssl ca -batch  -startdate 20161218120000Z -cert ca.crt -keyfile ca.key -out "${host}.crt" -infiles "${host}.csr"
done
#copy public ssl certs to all hosts
for host in ${hadoop_hosts[@]}; do
    sudo scp -o StrictHostKeyChecking=no -i $ssh_id ca.crt hadoop@$host:/tmp/ca.crt
    ssh -o StrictHostKeyChecking=no -i $ssh_id hadoop@$host "keytool -import -noprompt -alias zerodbca -file /tmp/ca.crt -storepass changeit -keystore $trust_store"
    for cert in ${hadoop_hosts[@]}; do
        scp -o StrictHostKeyChecking=no -i $ssh_id $cert.crt hadoop@${host}:/tmp/$cert.crt
        ssh -o StrictHostKeyChecking=no -i $ssh_id hadoop@$host "keytool -import -noprompt -alias $cert -file /tmp/$cert.crt -storepass changeit -keystore $trust_store; rm -f /tmp/$cert.crt"
    done
done
# hadoop host p12 files
for host in ${hadoop_hosts[@]}; do
    if [ -e "$host.p12" ]; then continue; fi
    sudo openssl pkcs12 -export -in "$host.crt" -inkey "$host.key" -out "$host.p12" -name $host -CAfile ca.crt -chain -passout pass:password
done
# hadoop private keystore
for host in ${hadoop_hosts[@]}; do
    sudo scp -o StrictHostKeyChecking=no -i $ssh_id $host.p12 hadoop@$host:/tmp/$host.p12
    ssh -o StrictHostKeyChecking=no -i $ssh_id hadoop@$host "
        sudo keytool -import -noprompt -alias zerodbca -file /tmp/ca.crt -storepass password -keypass password -keystore /etc/hadoop/conf/hadoop-private-keystore.jks
        sudo keytool --importkeystore -noprompt -deststorepass password -destkeypass password -destkeystore /etc/hadoop/conf/hadoop-private-keystore.jks -srckeystore /tmp/$host.p12 -srcstoretype PKCS12 -srcstorepass password -alias $host
        sudo chmod 440 /etc/hadoop/conf/hadoop-private-keystore.jks
        sudo chown yarn:hadoop /etc/hadoop/conf/hadoop-private-keystore.jks
        sudo rm -f /tmp/ca.crt \"/tmp/$host.p12\";
        "
done
}

install_jce_ext(){
sudo wget $download_url/$root_krb/jce_policy-8.zip
sudo unzip -o -j -q jce_policy-8.zip -d $java_lib_security_dir

echo "
sudo wget $download_url/$root_krb/jce_policy-8.zip
if [[ \$? -ne 0  ]];then
	echo \"Error can't find jce_policy-8.zip on $download_url\"
	exit 1
fi
sudo unzip -o -j -q jce_policy-8.zip -d $java_lib_security_dir
"> $remote_cmd
echo "run install jce ext remote script using $data_node_file"
run_remote_cmd $remote_cmd $data_node_file
}

enable_krb_hadoop_conf(){
sudo wget $download_url/$root_krb/enable_krb_hadoop.py 
sudo chmod u+x enable_krb_hadoop.py
sudo python enable_krb_hadoop.py
echo "
sudo wget $download_url/$root_krb/enable_krb_hadoop.py 
sudo chmod u+x enable_krb_hadoop.py
sudo python enable_krb_hadoop.py
"> $remote_cmd
echo "run enable krb hadoop conf remote script using $data_node_file"
run_remote_cmd $remote_cmd $data_node_file
}

install_krb_client(){
echo "install kerberos client on master"
sudo yum -y install krb5-workstation
sudo wget $download_url/$root_krb/krb5.conf
if [[ $? -ne 0  ]];then
	echo "Error can't find krb5.conf file on $download_url"
	exit 1
fi
sudo cp krb5.conf /etc
echo "install kerberos client on nodes"
echo "
sudo yum -y install krb5-workstation
sudo wget $download_url/$root_krb/krb5.conf
if [[ \$? -ne 0  ]];then
	echo \"Error can't find krb5.conf file on $download_url\"
	exit 1
fi
sudo cp krb5.conf /etc
"> $remote_cmd
run_remote_cmd $remote_cmd $data_node_file
}

install_keytabs(){
echo "install keytabs master"
h=$(hostname -f)
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q "addprinc -randkey hdfs/$h@ZERODB.LOCAL"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q "addprinc -randkey yarn/$h@ZERODB.LOCAL"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q "addprinc -randkey mapred/$h@ZERODB.LOCAL"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q "addprinc -randkey HTTP/$h@ZERODB.LOCAL"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q "addprinc -randkey HTTP/localhost@ZERODB.LOCAL"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q "ktadd -k hdfs.keytab hdfs/$h HTTP/$h"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q "ktadd -k mapred.keytab mapred/$h HTTP/$h"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q "ktadd -k yarn.keytab yarn/$h HTTP/$h"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q "ktadd -k http.keytab HTTP/localhost"
#
if [[ ! -f hdfs.keytab ]]; then
	if [[ $? -ne 0  ]];then
		echo "Error keytab file missing file"
		exit 1
	fi
fi
sudo mv hdfs.keytab mapred.keytab yarn.keytab /etc/hadoop/conf/
sudo mv http.keytab /etc/hadoop-kms/conf/
sudo chown hdfs:hadoop /etc/hadoop/conf/hdfs.keytab
sudo chown mapred:hadoop /etc/hadoop/conf/mapred.keytab
sudo chown yarn:hadoop /etc/hadoop/conf/yarn.keytab
sudo chown kms:hadoop /etc/hadoop-kms/conf/http.keytab
sudo chmod 400 /etc/hadoop/conf/*.keytab
sudo chmod 400 /etc/hadoop-kms/conf/*.keytab
echo "install keytabs to host : hosts"
echo "
h=\$(hostname -f)
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q \"addprinc -randkey hdfs/\$h@ZERODB.LOCAL\"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q \"addprinc -randkey yarn/\$h@ZERODB.LOCAL\"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q \"addprinc -randkey mapred/\$h@ZERODB.LOCAL\"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q \"addprinc -randkey HTTP/\$h@ZERODB.LOCAL\"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q \"addprinc -randkey HTTP/localhost@ZERODB.LOCAL\"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q \"ktadd -k hdfs.keytab hdfs/\$h HTTP/\$h\"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q \"ktadd -k mapred.keytab mapred/\$h HTTP/\$h\"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q \"ktadd -k yarn.keytab yarn/\$h HTTP/\$h\"
sudo kadmin -p $kdc_admin_principal -w $kdc_admin_pass -q \"ktadd -k http.keytab HTTP/localhost\"
#
sudo mv hdfs.keytab mapred.keytab yarn.keytab /etc/hadoop/conf/
sudo mv http.keytab /etc/hadoop-kms/conf/
sudo chown hdfs:hadoop /etc/hadoop/conf/hdfs.keytab
sudo chown mapred:hadoop /etc/hadoop/conf/mapred.keytab
sudo chown yarn:hadoop /etc/hadoop/conf/yarn.keytab
sudo chown kms:hadoop /etc/hadoop/conf/http.keytab
sudo chmod 400 /etc/hadoop/conf/*.keytab
sudo chmod 400 /etc/hadoop-kms/conf/*.keytab
" > $remote_cmd
run_remote_cmd $remote_cmd $data_node_file
}

function gen_datanode_file(){
echo "generating data nodes files before stoping cluster"
hdfs dfsadmin -report | grep ^Name | cut -f2 -d: | cut -f2 -d' ' > $data_node_file
if [[ $? -ne 0  ]];then
	echo "Error can't create datanodes files"
	exit 1
fi
gen_hadoop_hosts
}

# ssh id
if [[ ! -f $ssh_id ]]; then
	## add ssh id to master
	wget $download_url/$ssh_id
	if [[ $? -ne 0  ]];then
		echo "Error can't get cluster identity file"
		exit 1
	fi
	chmod 700 $ssh_id
fi
# check data node file
if [[ ! -f $data_node_file ]];then
	gen_datanode_file
fi

if [[ ! -f $data_node_file ]];then
	echo "Error : datanodes file "
    exit 1
fi

case "$1" in
	start)
		ops_master_srv start
		sleep 5
		ops_node_srv start
        ;;
	stop)
		ops_node_srv stop
		sleep 5
		ops_master_srv stop
		;;
	install_kerberos_client)
		install_krb_client
		;;
	install_jce_ext)
		install_jce_ext
		;;
	install_keytabs)
		install_keytabs
		;;
	enable_krb_hadoop_conf)
		enable_krb_hadoop_conf
		;;
	install_ssl_certs)
		gen_ssl_certs
		;;
	*)
		echo "usage : $0 start | stop | install_kerberos_client | install_jce_ext | install_keytabs | enable_krb_hadoop_conf | install_ssl_certs"
		;;
esac
