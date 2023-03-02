#
# Copyright 2021, 2023 NXP
#

examples := pkcs-keyop pkcs-key-provision hse-encrypt hse-sysimg hse-secboot trustzone-key-provision pkcs-cipher pkcs-msg-digest pkcs-sig
default_examples := pkcs-keyop pkcs-key-provision hse-encrypt hse-sysimg hse-secboot pkcs-cipher pkcs-msg-digest pkcs-sig
clean_examples = $(addprefix clean_,$(default_examples))
install_examples = $(addprefix install_,$(default_examples))

.PHONY: all clean $(examples) $(clean_examples)

define generate_build_rule
$(1):
	make -C ./$(1)
endef

define generate_clean_rule
clean_$(1):
	make -C ./$(1) clean
endef

define generate_install_rule
install_$(1):
	make -C ./$(1) install
endef

all: $(default_examples)
clean: $(clean_examples)
install: $(install_examples)

$(foreach example, $(examples), $(eval $(call generate_build_rule,$(example))))
$(foreach example, $(examples), $(eval $(call generate_clean_rule,$(example))))
$(foreach example, $(examples), $(eval $(call generate_install_rule,$(example))))
