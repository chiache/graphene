rust_target = stable-x86_64-unknown-linux-gnu
rust_home = build

test_files = test_files

exec_target = $(addsuffix .manifest,ld collect2 cc rustc)

clean-extra = clean-garbages

huge_rule = sys.stack.size = 64M\nsys.brk.size = 256M\nglibc.heap_size = 16M\nsgx.enclave_size = 2G

extra_rules = \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g' \
	-e 's:\$$(RUSTDIR):$(rust_home)/toolchains/$(rust_target):g' \
	-e 's:\$$(RUSTTARGET):$(rust_target):g' \
	-e 's:\$$(GCCDIR):$(patsubst %/cc1,%,$(shell gcc -print-file-name=cc1)):g' \
	-e 's:\$$(HUGERULE):$(if $(HUGE),$(huge_rule),):g'

level = ../../
include ../../Makefile

rustc.manifest: $(rust_home)/bin/rustc

$(rust_home)/bin/rustc:
	CARGO_HOME=$(abspath $(rust_home)) RUSTUP_HOME=$(abspath $(rust_home)) \
		   bash -c 'curl https://sh.rustup.rs -sSf | sh -s -- -y'

regression:
	@echo "\n\nBuilding Rust..."
	@$(MAKE) >> /dev/null 2>&1

	@echo "\n\nCompile hello.rs:"
	-./gcc.manifest test_files/helloworld.rs -o test_files/hello
	@chmod 755 test_files/hello
	-./test_files/hello
	@rm -f test_files/hello

distclean: clean
	rm -rf $(rust_home)

clean-garbages:
	rm -rf cc*.s cc*.c cc*.ld cc*.le cc*.o a.out
