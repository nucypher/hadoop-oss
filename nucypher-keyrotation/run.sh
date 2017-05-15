
curpath=`pwd`
./bin/hadoop jar prkeyrotation-0.0.1-SNAPSHOT.jar com.nucypher.prkeyrotation.Client    hdfs:///user/prkeyrotation-0.0.1-SNAPSHOT.jar  /enczone1 $curpath/nucypher-crypto-0.0.1-SNAPSHOT.jar,$curpath/bcprov-jdk15on-1.54.jar
