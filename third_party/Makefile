.PHONY: all
all: apktool/apktool.jar dex2jar/d2j-dex2jar.sh procyon/procyon-decompiler.jar vdexExtractor/bin/vdexExtractor

# dex2jar requires gradle Gradle 4.x, which is in Debian. apktool requires >= 5.x, which
# isn’t, so use gradlew there. We can’t use gradlew for Gradle 4.x, because it can’t parse
# the Java version from ‘11.0.4’.
GRADLE4 ?= gradle
GRADLE5 ?= ./gradlew

MVN ?= mvn # Tested with 3.6.1

.PHONY: clean
clean:
	cd apktool && rm -f apktool.jar && $(GRADLE5) clean
	cd dex2jar && rm -f *.sh && rm -rf out && $(GRADLE4) clean && rm -rf .gradle
	cd procyon && rm -f procyon-decompiler.jar && $(GRADLE4) clean && rm -rf .gradle
	cd vdexExtractor && ./make.sh clean
	rm -f linux.stamp && cd linux && make distclean

apktool/apktool.jar:
	cd apktool && \
	$(GRADLE5) shadowJar && \
	ln -sf brut.apktool/apktool-cli/build/libs/apktool-cli-all.jar apktool.jar

dex2jar/d2j-dex2jar.sh:
	cd dex2jar && \
	$(GRADLE4) distZip && \
	rm -rf out && \
	unzip -d out dex-tools/build/distributions/*.zip && \
	ln -sf out/dex-tools-*/*.sh .

procyon/procyon-decompiler.jar:
	cd procyon && \
	$(GRADLE4) fatJar && \
	ln -sf build/Procyon.Decompiler/libs/procyon-decompiler-*.jar procyon-decompiler.jar

vdexExtractor/bin/vdexExtractor:
	cd vdexExtractor && ./make.sh

linux.stamp:
ifndef LINUX_CROSS
	$(error set LINUX_CROSS to cross compiler prefix)
endif
	sed -i -e 's/^ *YYLTYPE yylloc;/extern &/' linux/scripts/dtc/dtc-lexer.*
	cp config-linux-3.10.79 linux/.config
	+cd linux && $(MAKE) ARCH=arm CROSS_COMPILE=$(LINUX_CROSS) oldconfig modules
	touch linux.stamp
