JAVA_HOME = $(shell readlink -f /usr/bin/javac | sed "s:bin/javac::")
JAVAC = $(JAVA_HOME)/bin/javac

target = $(patsubst %.java,%.class,$(wildcard classes/*.java))
exec_target = java.manifest

clean-extra = clean-classes

ifeq ($(HUGE),)
RESOURCE_RULE = sys.stack.size = 256K\nsys.brk.size = 16M\nglibc.heap_size =  4M\nsgx.enclave_size = 256M\nsgx.thread_num = 12
else
RESOURCE_RULE = sys.stack.size = 4M\nsys.brk.size = 64M\nglibc.heap_size = 16M\nsgx.enclave_size = 8G\nsgx.thread_num = 32
endif

extra_rules = \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g' \
	-e 's:\$$(JAVA_HOME):$(JAVA_HOME):g' \
	-e 's:\$$(RESOURCE_RULE):$(RESOURCE_RULE):g'

level = ../../
include ../../Makefile

%.class: %.java $(JAVAC)
	$(JAVAC) $<

clean-classes:
	rm -f classes/*.class
