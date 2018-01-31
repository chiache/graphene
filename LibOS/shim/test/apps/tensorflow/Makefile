PYTHON_INSTALL = build
PYTHON_INSTALL_DIR = $(shell readlink -f $(PYTHON_INSTALL))

manifests = python.manifest

target = $(PYTHON_INSTALL)/bin/python
exec_target = $(manifests)

extra_rules = -e 's:\$$(PYTHONDIR):$(PYTHON_INSTALL):g'
clean-extra += clean-tmp

level = ../../
include ../../Makefile

$(PYTHON_INSTALL)/bin/python: tensorflow-build.tar.xz
	tar -xmJf $<

clean-tmp:
	rm -f python.manifest.sgx

distclean: clean
	rm -rf $(PYTHON_SRC) $(PYTHON_INSTALL)
