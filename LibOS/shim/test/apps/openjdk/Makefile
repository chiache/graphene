JAVA_HOME = $(shell readlink -f /usr/bin/javac | sed "s:/bin/javac::")
JAVAC = $(JAVA_HOME)/bin/javac

target = $(patsubst %.java,%.class,$(wildcard classes/*.java))
exec_target = java.manifest

clean-extra = clean-classes

extra_rules = \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g' \
	-e 's:\$$(JAVA_HOME):$(JAVA_HOME)/jre:g'

level = ../../
include ../../Makefile

%.class: %.java $(JAVAC)
	$(JAVAC) $<

clean-classes:
	rm -f classes/*.class
