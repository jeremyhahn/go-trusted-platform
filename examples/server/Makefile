APPBIN             ?= tpadm

PLATFORM_DIR       ?= trusted-data
CONFIG_DIR         ?= $(PLATFORM_DIR)/etc
LOG_DIR            ?= $(PLATFORM_DIR)/log
CA_DIR             ?= $(PLATFORM_DIR)/ca
DEFAULT_PASSWORD   ?= 123456

default: clean build run

env:
	@echo "APPBIN: \t\t$(APPBIN)"
	@echo "PLATFORM_DIR: \t\t$(PLATFORM_DIR)"
	@echo "CONFIG_DIR: \t\t$(CONFIG_DIR)"
	@echo "LOG_DIR: \t\t$(LOG_DIR)"
	@echo "CA_DIR: \t\t$(CA_DIR)"
	@echo "DEFAULT_PASSWORD: \t$(DEFAULT_PASSWORD)"

build:
	cd ../../ && make


clean:
	rm -rf $(PLATFORM_DIR)


run:
	../../$(APPBIN) webservice \
		--debug \
		--init \
		--platform-dir $(PLATFORM_DIR) \
    	--log-dir $(LOG_DIR) \
		--ca-dir $(CA_DIR) \
		--raw-so-pin $(DEFAULT_PASSWORD) \
		--raw-pin $(DEFAULT_PASSWORD)
