TENSORFLOW_INSTALL = tensorflow
TENSORFLOW_URL = https://storage.googleapis.com/tensorflow/linux/cpu/tensorflow-1.5.0-cp27-none-linux_x86_64.whl
TENSORFLOW_EXTRA_PACKAGES = pandas sklearn scipy

PYTHON_SRC = Python-2.7.9
PYTHON_INSTALL = python-install

manifests = python.manifest
target = install-tensorflow install-extra-packages
extra_rules = -e 's:\$$(TENSORFLOWDIR):$(TENSORFLOW_INSTALL):g' \
              -e 's:\$$(PYTHONDIR):$(PYTHON_INSTALL):g'

exec_target = $(manifests)

clean-extra += clean-tmp

level = ../../
include ../../Makefile

$(PYTHON_INSTALL)/bin/python: $(PYTHON_SRC)/Makefile
	cd $(PYTHON_SRC) && $(MAKE)
	cd $(PYTHON_SRC) && $(MAKE) install

$(PYTHON_INSTALL)/bin/easy_install: $(PYTHON_INSTALL)/bin/python
	$(PYTHON_INSTALL)/bin/python ez_setup.py

$(PYTHON_INSTALL)/bin/virtualenv: $(PYTHON_INSTALL)/bin/easy_install
	$(PYTHON_INSTALL)/bin/easy_install -i https://pypi.python.org/simple/ virtualenv

$(PYTHON_SRC)/Makefile: $(PYTHON_SRC)/configure
	cd $(PYTHON_SRC) && \
		./configure --prefix=$(shell readlink -f $(PYTHON_INSTALL)) --enable-unicode=ucs4

$(PYTHON_SRC)/configure: $(PYTHON_SRC).tgz
	tar -xmzf $<

$(TENSORFLOW_INSTALL)/bin/activate: $(PYTHON_INSTALL)/bin/virtualenv
	$(PYTHON_INSTALL)/bin/virtualenv --system-site-packages $(TENSORFLOW_INSTALL)

.PHONY: install-tensorflow
install-tensorflow: $(TENSORFLOW_INSTALL)/bin/activate
	bash -c "source $(TENSORFLOW_INSTALL)/bin/activate; \
		easy_install -U pip && \
		pip install --upgrade $(TENSORFLOW_URL)"

.PHONY: install-extra-packages
install-extra-packages: $(TENSORFLOW_INSTALL)/bin/activate
	bash -c "source $(TENSORFLOW_INSTALL)/bin/activate; \
		easy_install -U pip && \
		pip install --upgrade $(TENSORFLOW_EXTRA_PACKAGES)"

clean-tmp:
	rm -f python.manifest python.manifest.sgx

distclean: clean
	rm -rf $(PYTHON_SRC) $(PYTHON_INSTALL) $(TENSORFLOW_INSTALL)
