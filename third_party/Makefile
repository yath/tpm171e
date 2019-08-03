.PHONY: all
all: apktool/apktool.jar dex2jar/d2j-dex2jar.sh jd-cmd/out/jd-cli vdexExtractor/bin/vdexExtractor

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
	cd jd-cmd && rm -rf out && $(MVN) clean
	cd vdexExtractor && ./make.sh clean

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

jd-cmd/out/jd-cli:
	cd jd-cmd && \
	$(MVN) package && \
	unzip -d out *-dist.zip

vdexExtractor/bin/vdexExtractor:
	cd vdexExtractor && ./make.sh
