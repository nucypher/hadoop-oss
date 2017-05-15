
mvn dependency:copy-dependencies

java -cp ./target/dependency/jep-3.5.2.jar:./target/dependency/nucypher-crypto-0.0.1-SNAPSHOT.jar:./target/prkeyrotation-0.0.1-SNAPSHOT.jar -Djava.library.path=/Users/snowman/code/test/jep1/lib/python2.7/site-packages/jep/  com.nucypher.prkeyrotation.TestMaterialGenerator
