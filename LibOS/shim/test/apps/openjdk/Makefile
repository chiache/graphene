JAVA_HOME ?= $(shell readlink -f /usr/bin/java | sed "s:/bin/java::")
JAVAC = $(JAVA_HOME)/bin/javac

CLASSES = $(patsubst %.java,%.class,$(wildcard classes/*.java))
SUITES = classes/apache-sshd-1.2.0/sshd-core/target/sshd-core-1.2.0.jar \
	 classes/jmh-jdk-1.0/target/jmh-jdk-microbenchmarks-1.0-SNAPSHOT.jar

target = $(CLASSES) $(SUITES)
exec_target = java.manifest

clean-extra = clean-classes

extra_rules = \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g' \
	-e 's:\$$(JAVA_HOME):$(JAVA_HOME):g'

level = ../../
include ../../Makefile

%.class: %.java
	javac $<

classes/apache-sshd-1.2.0/sshd-core/target/sshd-core-1.2.0.jar:
	cd classes && wget http://archive.apache.org/dist/mina/sshd/1.2.0/apache-sshd-1.2.0-src.tar.gz
	cd classes && tar -xzf apache-sshd-1.2.0-src.tar.gz
	cd classes/apache-sshd-1.2.0 && mvn install -Dcheckstyle.skip -Dmaven.test.skip=true

classes/jmh-jdk-1.0/target/jmh-jdk-microbenchmarks-1.0-SNAPSHOT.jar:
	cd classes && wget http://hg.openjdk.java.net/code-tools/jmh-jdk-microbenchmarks/archive/tip.tar.gz -O jmh-jdk-1.0.tar.gz
	cd classes && mkdir -p jmh-jdk-1.0
	cd classes/jmh-jdk-1.0 && tar -xzf ../jmh-jdk-1.0.tar.gz --strip-components=1
	cd classes/apache-sshd-1.2.0 && mvn install -Dcheckstyle.skip -Dmaven.test.skip=true

clean-classes:
	rm -f classes/*.class
