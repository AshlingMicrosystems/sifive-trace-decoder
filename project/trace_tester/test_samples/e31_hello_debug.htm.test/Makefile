
ifeq ($(DQRPATH),)
    DQR := $(shell which dqr)
    DQRTP := $(realpath $(dir $(DQR))..)
else
    DQRTP := $(realpath $(DQRPATH))
endif

ifneq ($(OBJDUMP),)
    OD := -od $(subst :,\\,$(subst \,:,$(OBJDUMP)))
else
    OD :=
endif

BINPATH := $(DQRTP)/bin
LIBPATH := $(DQRTP)/lib
JAVAPATH := $(DQRTP)/examples/java

ifeq ($(OS),Windows_NT)
    ifeq ($(DQREXE),)
        DQREXE := $(BINPATH)/dqr.exe
    endif

    ifeq ($(DQRLIB),)
        DQRLIB := $(LIBPATH)/dqr.dll
    endif

    PLATFORM := windows
else
    ifeq ($(DQREXE),)
        DQREXE := $(BINPATH)/dqr
    endif

    ifeq ($(DQRLIB),)
        DQRLIB := $(LIBPATH)/dqr.so
    endif

    PLATFORM := unix
endif

ifeq ($(RESULTPATH),)
    RSLTPATH := $(realpath .)
else
    RSLTPATH := $(realpath $(RESULTPATH))
endif

ifeq ($(LS),)
    LS := ls -l
endif

TESTNAME := $(patsubst %.rtd,%,$(wildcard *.rtd))

RESULTNAME := $(lastword $(subst /, ,$(shell pwd)))

.PHONY: test clean result update

test: $(TESTNAME).pass

clean:
	rm -f result.log $(TESTNAME).pass $(TESTNAME).fail
	rm -f $(TESTNAME).stdout $(TESTNAME).stderr
	rm -f reference/$(TESTNAME).stdout reference/$(TESTNAME).stderr

result:
	if [ -e $(TESTNAME).pass ]; then \
		echo PASS: $(RESULTNAME) `date -r $(TESTNAME).pass` >> $(RSLTPATH)/result.log; \
	else if [ -e $(TESTNAME).fail ]; then \
			echo FAIL: $(RESULTNAME) `date -r $(TESTNAME).fail` >> $(RSLTPATH)/result.log; \
		else \
			echo NOT RUN: $(RESULTNAME) >> $(RSLTPATH)/result.log; \
		fi \
	fi

update:
	cp $(TESTNAME).stdout reference/$(TESTNAME).stdout
	cp $(TESTNAME).stderr reference/$(TESTNAME).stderr
	cd reference; zip -u $(TESTNAME).stdout.zip $(TESTNAME).stdout
	cd reference; zip -u $(TESTNAME).stderr.zip $(TESTNAME).stderr

reference/$(TESTNAME).stdout: reference/$(TESTNAME).stdout.zip
	cd reference; unzip -o $(TESTNAME).stdout.zip $(notdir $@); touch $(notdir $@)

reference/$(TESTNAME).stderr: reference/$(TESTNAME).stderr.zip
	cd reference; unzip -o $(TESTNAME).stderr.zip $(notdir $@); touch $(notdir $@)

$(TESTNAME).pass: reference/$(TESTNAME).stdout reference/$(TESTNAME).stderr
	rm -f $(TESTNAME).pass $(TESTNAME).fail
	$(DQREXE) -t $(TESTNAME).rtd -e $(TESTNAME).elf -src -branches -callreturn -analytics=2 $(OD) > $(TESTNAME).stdout 2> $(TESTNAME).stderr \
		|| (echo FAIL: $(RESULTNAME); touch $(TESTNAME).fail; false)
	diff -q --strip-trailing-cr $(TESTNAME).stdout reference/$(TESTNAME).stdout \
		|| (echo FAIL: $(RESULTNAME); touch $(TESTNAME).fail; false)
	diff -q --strip-trailing-cr $(TESTNAME).stderr reference/$(TESTNAME).stderr \
		|| (echo FAIL: $(RESULTNAME); touch $(TESTNAME).fail; false)
	touch $(TESTNAME).pass
	@echo PASS: $(RESULTNAME)
