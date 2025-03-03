# platform: portable64 ref avx2 avx512
platform := $(PLATFORM)
subdirs := $(VARIANT)

.PHONY: all clean $(subdirs)

all: $(subdirs)

$(subdirs): qruov_config.src
	# aes
	mkdir -p $@/$(platform)a
	grep $@ qruov_config.src > $@/$(platform)a/qruov_config.txt
	sh -c "cd $@/$(platform)a ; ln -s ../../$(platform)/* . || true"
	$(MAKE) -C $@/$(platform)a
	# shake
	#mkdir -p $@/$(platform)s
	#echo -n " -DQRUOV_PRG_SHAKE " > $@/$(platform)s/qruov_config.txt
	#grep $@ qruov_config.src >> $@/$(platform)s/qruov_config.txt
	#sh -c "cd $@/$(platform)s ; ln -s ../../$(platform)/* . || true"
	#$(MAKE) -C $@/$(platform)s

clean:
	rm -rf $(subdirs)
