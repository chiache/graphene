LOCAL := 1

PYTHON_SRC = Python-2.7.9
PYTHON_INSTALL = python-install

manifests = python.manifest

ifeq ($(LOCAL),1)
target = $(PYTHON_INSTALL)/bin/python
manifests += python-local.manifest
extra_rules = -e 's:\$$(PYTHONDIR):$(PYTHON_INSTALL):g'
endif

exec_target = $(manifests)

clean-extra += clean-tmp

level = ../../
include ../../Makefile

ifeq ($(LOCAL),1)
$(PYTHON_INSTALL)/bin/python: $(PYTHON_SRC)/Makefile
	cd $(PYTHON_SRC) && $(MAKE)
	cd $(PYTHON_SRC) && $(MAKE) install

$(PYTHON_SRC)/Makefile: $(PYTHON_SRC)/configure
	cd $(PYTHON_SRC) && \
		./configure --prefix=$(shell readlink -f $(PYTHON_INSTALL))

$(PYTHON_SRC)/configure: $(PYTHON_SRC).tgz
	tar -xmzf $<
endif

clean-tmp:
	rm -f python.manifest python.manifest.sgx python-local.manifest python-local.manifest.sgx

distclean: clean
	rm -rf $(PYTHON_SRC) $(PYTHON_INSTALL)
