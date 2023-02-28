#
# Copyright 2021, 2023 NXP
#

examples :=  pkcs-keyop pkcs-key-provision hse-encrypt hse-sysimg hse-secboot
clean_examples = $(addprefix clean_,$(examples))
install_examples = $(addprefix install_,$(examples))

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

all: $(examples)
clean: $(clean_examples)
install: $(install_examples)

$(foreach example, $(examples), $(eval $(call generate_build_rule,$(example))))
$(foreach example, $(examples), $(eval $(call generate_clean_rule,$(example))))
$(foreach example, $(examples), $(eval $(call generate_install_rule,$(example))))
