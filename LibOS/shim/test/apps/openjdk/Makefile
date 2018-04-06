JAVA_HOME ?= $(shell readlink -f /usr/bin/java | sed "s:/bin/java::")
JAVAC = $(JAVA_HOME)/bin/javac

target = $(patsubst %.java,%.class,$(wildcard classes/*.java))
exec_target = java.manifest

clean-extra = clean-classes

extra_rules = \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g' \
	-e 's:\$$(JAVA_HOME):$(JAVA_HOME):g'

level = ../../
include ../../Makefile

%.class: %.java
	javac $<

clean-classes:
	rm -f classes/*.class
