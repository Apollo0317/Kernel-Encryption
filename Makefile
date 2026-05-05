
all: build-krn build-usr

build-krn:
	$(MAKE) -C kmod

build-usr:
	$(MAKE) -C app

install:
	$(MAKE) -C kmod install

insmod:
	$(MAKE) -C kmod insmod

rmmod:
	$(MAKE) -C kmod rmmod

clean:
	$(MAKE) -C kmod clean
	$(MAKE) -C app clean
