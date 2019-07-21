include Pal/src/Makefile.Host

targets = all clean format

.PHONY: $(targets)
$(targets):
	$(MAKE) -C Pal $@
	$(MAKE) -C LibOS $@
	$(MAKE) -C Runtime $@

.PHONY: install
install:
	@echo "\"make install\" is deprecated. use \"make\" instead."

ifeq ($(BUILD_LINUX_BINARIES),false)

# Listing directories that need to be built in Linux
LINUX_BINARIES = Runtime/ \
		 $(addprefix Pal/,test regression) \
		 $(addprefix LibOS/shim/test/,native regression benchmark)

ARTIFACT = graphene-binaries.tar

DOCKER_IMAGE = graphene:$(shell git rev-parse --short HEAD)
DOCKER_NAME = $(shell echo graphene_$$RANDOM)
DOCKER_CMD = \
	git clone https://github.com/chiache/graphene.git -b fix-freebsd --depth=1 && \
	cd graphene && \
	make && \
	git ls-files --others --exclude-standard -z -i $(LINUX_BINARIES) \
	| xargs -0 tar rvf ~/$(ARTIFACT)

$(ARTIFACT):
	[ ! -z $(docker images -q $(DOCKER_IMAGE)) ] || cd Jenkinsfiles && docker build -t $(DOCKER_IMAGE) -f ubuntu-16.04.dockerfile .
	docker run --name $(DOCKER_NAME) -it $(DOCKER_IMAGE) /bin/bash -c "$(DOCKER_CMD)"
	docker cp $(DOCKER_NAME):/leeroy/$(ARTIFACT) $(ARTIFACT)
	docker rm $(DOCKER_NAME)
	docker rmi $(DOCKER_IMAGE)

endif
