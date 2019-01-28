# TPM171E

This page collects some technical information for the Philips (a.k.a. TPVision)
Android TV; specifically, for my 2018 65OLED863 series. Addresses may vary.

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
mine. The CLI knows a default “guest” mode and a higher-privileged “guest” mode.
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

I haven’t really played around with anything else than the memory read/write
operations to get some code running. But see the [Makefile](Makefile) for how to
link and run code in the kernel.
