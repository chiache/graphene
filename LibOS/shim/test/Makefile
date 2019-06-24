subdirs = native

SYS ?= $(shell gcc -dumpmachine)
export SYS

PALDIR  = $(level)../../../Pal/src
SHIMDIR = $(level)../src
RUNTIME = $(level)../../../Runtime

ifeq ($(SGX),1)
PAL_LOADER = pal_loader SGX
else
PAL_LOADER = pal_loader
endif

CC = gcc
CXX = g++
CFLAGS 	= -Wall -std=gnu99
CFLAGS-debug = $(CFLAGS) -I$(SHIMDIR)/../include -I$(PALDIR)/../include/pal -I$(PALDIR)/../lib
LDFLAGS	=
LDFLAGS-debug = $(LDFLAGS) -L$(SHIMDIR) -L$(PALDIR) -Wl,-rpath-link=$(abspath $(RUNTIME))

CFLAGS-libos = -I$(SHIMDIR)/../include -L$(SHIMDIR)/../../glibc-build/libos

.PHONY: default
default: all

include $(PALDIR)/Makefile.Test

.PHONY: all
all: pal_loader $(target) $(if $(level),,build-subdirs) | $(call expand_target,$(exec_target))

ifeq ($(DEBUG),1)
CC += -g
CXX += -g
endif
export DEBUG

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

include $(level)../../../Makefile.rules

manifest_rules = \
	$(call sed_sub,PAL,$(abspath $(RUNTIME))/$(PAL_LOADER)) \
	$(call sed_sub,PWD,$(shell pwd)) \

ifeq ($(ABSPATH_IN_MANIFEST),yes)
manifest_rules += \
	$(call sed_sub,BIN,$(subst .manifest,,$(notdir $@))) \
	$(call sed_sub,SHIMPATH,$(abspath $(RUNTIME))/libsysdb.so) \
	$(call sed_sub,LIBCDIR,$(abspath $(RUNTIME)))
else
manifest_rules += \
	$(call sed_sub,BIN,$(subst .manifest,,$(notdir $@))) \
	$(call sed_sub,SHIMPATH,'$$RELDIR'$(RUNTIME)/libsysdb.so) \
	$(call sed_sub,LIBCDIR,'$$RELDIR'$(RUNTIME))
endif

manifest_rules += $(extra_rules)

pal_loader: $(RUNTIME)/pal_loader
	$(call cmd,ln_sf)

relative-to = $(shell python -c "import os.path; print os.path.relpath(\"$(abspath $2)\",\"$(abspath $1)\")")

%manifest: %manifest.template
	@echo [ $@ ]
	@RELDIR=$(filter-out ./,$(call relative-to,$(dir $@),$(shell pwd))/) && \
	$(call sed,$(manifest_rules))
	@(grep -q '^#!' $@ && chmod +x $@) || true

manifest: manifest.template
	@echo [ $@ ]
	@$(call sed,$(manifest_rules))

.PHONY: clean
clean: $(clean-extra) $(if $(level),,clean-subdirs)
	rm -rf pal_loader $(call expand_target,$(exec_target)) $(target)

.PHONY: build-subdirs
build-subdirs:
	for f in $(subdirs); do (cd $$f; $(MAKE); cd ..); done

.PHONY: clean-subdirs
clean-subdirs:
	for f in $(subdirs); do (cd $$f; $(MAKE) clean; cd ..); done
