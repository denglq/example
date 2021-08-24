ifdef DEFINE_VRE
VRE = “Hello World!”
else
endif

ifeq ($(OPT),define)
	VRE ?= “Hello World! First!”
endif


ifdef OPT
DEF="def opt"
else
endif
$(info $(DEF))

ifeq ($(OPT),add)
	VRE += “Kelly!”
endif

ifeq ($(OPT),recover)
	VRE := “Hello World! Again!”
endif
$(info $(wildcard $(RTE_SDK)/*/.config))
$(info $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config))))
$(info $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))
$(info $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config))))))


var=3

all:
	echo "do all"
	@echo "do all"
	@echo $(VRE)
