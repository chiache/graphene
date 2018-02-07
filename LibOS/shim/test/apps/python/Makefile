LOCAL ?= 0

PYTHON_SRC = Python-2.7.9
PYTHON_INSTALL = python-install

manifests = python.manifest

ifeq ($(LOCAL),1)
target = $(addprefix $(PYTHON_INSTALL)/bin/,python easy_install virtualenv)
manifests += python-local.manifest
extra_rules = -e 's:\$$(PYTHONDIR):$(PYTHON_INSTALL):g'
endif

target += benchmarks
exec_target = $(manifests)

clean-extra += clean-tmp

level = ../../
include ../../Makefile

ifeq ($(LOCAL),1)
$(PYTHON_INSTALL)/bin/python: $(PYTHON_SRC)/Makefile
	cd $(PYTHON_SRC) && $(MAKE)
	cd $(PYTHON_SRC) && $(MAKE) install

$(PYTHON_INSTALL)/bin/easy_install: $(PYTHON_INSTALL)/bin/python
	$(PYTHON_INSTALL)/bin/python ez_setup.py

$(PYTHON_INSTALL)/bin/virtualenv: $(PYTHON_INSTALL)/bin/easy_install
	$(PYTHON_INSTALL)/bin/easy_install -i https://pypi.python.org/simple/ virtualenv

$(PYTHON_SRC)/Makefile: $(PYTHON_SRC)/configure
	cd $(PYTHON_SRC) && \
		./configure --prefix=$(shell readlink -f $(PYTHON_INSTALL))

$(PYTHON_SRC)/configure: $(PYTHON_SRC).tgz
	tar -xmzf $<
endif

benchmarks: benchmarks.tar.gz
	tar -xmzf $<

regression: 
	@echo "\n\nBuilding Python..."
	@$(MAKE) >> /dev/null 2>&1

	@echo "\n\nRun helloworld.py:"
	-./python.manifest scripts/helloworld.py > OUTPUT
	-grep -q "Hello World" OUTPUT
	@rm OUTPUT

	@echo "\n\nRun fibonacci.py:"
	-./python.manifest scripts/fibonacci.py  > OUTPUT
	-grep -q "fib2              55" OUTPUT
	@rm -f OUTPUT

	./web-test.sh


BENCHMARK = all,-rietveld,-spitfire,-tornado_http

clean-tmp:
	rm -f python.manifest python.manifest.sgx python-local.manifest python-local.manifest.sgx

distclean: clean
	rm -rf $(PYTHON_SRC) $(PYTHON_INSTALL) benchmarks
