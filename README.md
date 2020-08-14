# TPM171E

This page collects some technical information for the Philips (a.k.a. TPVision)
Android TV; specifically, for my 2018 65OLED873 series (“TPM171E”).

**NOTE: This document is work in progress!**

## adb access

Install [telnetd](https://play.google.com/store/apps/details?id=com.waxrain.telnetd) from
Google Play, enable the adb service.

Enable developer options by tapping on the build number in the Android settings five times.
There, enable USB Debugging. Try `adb connect your.tv.address` from a computer. If no
confirmation dialog pops up and `adb shell` doesn’t work either, try rebooting (e.g. with
Ctrl+Alt+Del on a USB keyboard) and quickly connecting during boot. It may take a few tries,
but should succeed eventually.

Something in this sequence has temporarily made “USB 1” (the upper port) a USB *host*,
speaking the adb protocol (you’ll need a USB A-to-A cable). This seems to always be the
case in fastboot mode, out of which you can (apparently only) get with `fastboot continue`.
Don’t type `reboot bootloader`!

## Partitions

* mmcblk0boot0, mmcblk0p1 (uboot), p2 (ubootB): uboot.bin
* p3 (misc): ???
* p4 (recovery), p8 (recoveryB): recovery.img
* p5 (boot): boot.img (androidboot)
* p6 (uboot\_env), p7 (ubootB\_env): uenv
* p9 (bootB), p22 (tzbp): tz.bin.lzhs
* p10-p13: system, userdata, cache, dmverity
* p14 (linux\_rootfs): rootfs
* p15 (factory): factory
* p16 (factory\_setting): ???
* p17 (3rd\_ro): 3rd file
* p18-p21: 3rd\_rw, reserved, channelA, channelB
* p23 (adsp): adsp
* p24-p27: ciplus, dvbsDB, nvm, ambl
* p28 (pq): pq
* p29 (aq): aq
* p30-p33: SCHEDPVR, usersetting, basic

## Boot process

uboot.bin (mmcblk0p1 and 2) is comprised of `mtk_1bl`, the first-stage
bootloader. It decompresses `mtkloader`, which decompresses `uboot`. `uboot` is
an actual U-Boot bootloader (2011.12) and loads the ARM TrustZone kernel
(`lk/MP`) after decompressing `tz.bin` (p9/p22). TZ seems to load the
Linux kernel.

The TZ stuff seems entirely irrelevant in practice. An U-Boot shell can be
accessed through a serial console ([SERV.U
port](https://forum.xda-developers.com/android-tv/philips-sony-tcl-android-tv/philips-android-tv-t2935545/page35)),
boot args can be set and different partitions can be booted.

For example, to load a different Android boot image from `recoveryB` on `/dev/mmcblk0p8`
(which seems unused and its content otherwise matches `recovery`, so seems safe to
overwrite):

```
# Run 'getenv bootargs' beforehand and modify root= only
setenv bootargs lpj=120000 console=ttyMT0,115200n1 root=/dev/mmcblk0p8 vmalloc=650mb mtdparts=mt53xx-emmc:2M(uboot),2M(ubootB),1M(misc)enc,32M(recovery)enc,20M(boot)enc,2M(uboot_env)enc,2M(ubootB_env)enc,32M(recoveryB)enc,20M(bootB)enc,2048M(system),10288M(userdata),1200M(cache),1M(dmverity),61M(linux_rootfs),20M(factory),10M(factory_setting),128M(3rd_ro)enc,64M(3rd_rw)enc,1M(reserved),1M(channelA),1M(channelB),1M(tzbp)enc,4M(adsp),1M(ciplus),1M(dvbsDB),2M(nvm),1M(ambl),20M(pq),5M(aq),1M(SCHEDPVR),720M(usersetting),1M(basic) usbportusing=1,1,0,1 usbpwrgpio=42:1,43:1,44:1,210:1 usbocgpio=404:0,404:0,405:0,405:0 usbhubrstgpio=-1:-1 msdcgpio=76,-1,-1,176,-1,-1 msdcautok=0x200000a,0x242000,0x0,0x403c0007,0xfffe00c9,0x84821803,0x2e889f2,0x1030204,0x3030303,0x0,0x0,0x1201d,0x0,0x0,0x0,0x0,0x0 tzsz=48m no_console_suspend minigzip=1 forbid_uart0=1 perfor_uart0=0 gpustart=924712960 gpusize=0 gpuionsize=0 androidboot.serialno=000070af2414fb93 adb_enable=0 androidboot.hardware=mt5891 bootreason=reboot modelgroup=PHTV17AMT0 device_name=65OLED873/12
eboot recoveryB
```

Make sure that the `root=` partition matches the one you are booting with `eboot`, or your
kernel will use a different initrd and you might get surprising results.

## root

`make` the `loader` target and `adb push` it to `/data/local/tmp` or so. The first run
takes about two minutes, as the loader needs to acquire a thread dump to locate the
running kernel module address. It relocates the bundled `getroot.elf` to the address
of the `_CmdVersion` handler, writes it there, executes it via `b.ver` and `execve()`s
a shell.

## cli

### Technical details

`/dev/cli` is the debug interface to `dtv_driver.ko`. It supports some ioctls
(cf. `cli_ioctl()`).

* `ioctl(fd, 0, &char)`: Places a character into the UART input buffer.

* `ioctl(fd, 1, &str)`: Passes a (0-terminated) string to `CLI_Parser()`.

* `ioctl(fd, 0x100)`: Acquires a semaphore.

* `ioctl(fd, 0x101)`: Releases this semaphore.

* `ioctl(fd, 0x102, void*)`: Calls `DMX_SetCapture()` with the user-supplied argument.

* `ioctl(fd, 0x103, void*)`: Calls `DMX_GetCaptureInfo()` with the user-supplied argument.

I haven’t played around with any other ioctl than 0 or 1.

`/dev/cli` is writable by the shell user, but some (obscure) commands return `EPERM`. That
said, most don’t. `cli_shell` is a pre-installed binary that does (essentially) the following:

```
int fd = open("/dev/cli", O_RDWR);
system("echo 0 > /proc/sys/kernel/printk");
char *command = append(join(" ", argc, argv), "\r\n");
char c;
while (c = *command++)
  ioctl(fd, 0, &c);
system("echo 7 > /proc/sys/kernel/printk");
usleep(200000);
```

It is probably meant for a user on the serial console, to which the kernel log would
get printed. With adb access, you can simply run `logcat -s MTK_KL|tr \\r \\n`.

The [cli](cli.go) in this repository simplifies the access via adb. It only prints the
actual command output before exiting, by placing a sentinel alias before and after
the command, all of which are sent with ioctl _1_ instead of 0. I couldn’t see a
difference. It sometimes fails; if there is no output after a couple of seconds, and
the CLI isn’t blocked (e.g. by a running `b.da`), try hitting ^C and try again.

### The UI

`ls` gets you a list of (most) commands. See
[cmdlist-guest.txt](cmdlist-guest.txt) and [cmdlist-sv.txt](cmdlist-sv.txt) for
mine. The CLI knows a default “guest” mode and a higher-privileged “supervisor” mode.
The `b.sv` command is apparently meant to detect this based on some external
trigger, but `b.scm 0` (set cli mode?) lets us handily switch to supervisor mode
and `b.scm 2` back. See `_arDefaultCmdTbl` in `dtv_driver.ko` for all commands -
I couldn’t find any interesting hidden ones (`//` for line comment is one).

Generally, the _something_.q commands seem to query only and are probably harmless.
`.d_on`, `.d_off` and `.d_l` set/show debug/log levels.

Some random notes:

* `cust` or customer refers to Philips/TPVision. It’s likely that `dtv_driver.ko`
   was mostly written by Mediatek.

* The kernel and the modules are always loaded in the same order at the same addresses.

* `MID` refers to a “Memory Intrustion Detection” and probably is some [HDCP
   Nonsense](https://www.cs.auckland.ac.nz/~pgut001/pubs/vista_cost.html). It does
   nothing about the kernel, however, which starts at `0xc0008000`.

* `linuxmode` puzzles me a bit, it seems to move the base offsets for the memory
   read/write commands only. My current guess is that some other CPU (which is
   the “Linux” one, as opposed to the “Android” one) has its memory mapped to
   that offset and one can poke around on the other CPU.

*  The code has little error checking, to put it mildly. E.g. the `do` command
   for repeating a CLI command locks up with `do 0 ls`.

* `b.da` gives a thread dump of the kernel portion of all tasks.

* `dtv_driver` calls its own `CLI_Parser` (which has a global mutex) every once
   in a while.

*  The `printk()`s are full of carriage-returns that you may want to strip
   off when viewing logcat output.

I haven’t really played around with anything else than the memory read/write
operations to get some code running. But see the [Makefile](Makefile) for how to
link and run code in the kernel.
