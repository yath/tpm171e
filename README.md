# TPM171E

This page collects some technical information for the Philips (a.k.a. TPVision)
Android TV; specifically, for my 2018 65OLED803 series. Addresses may vary.

NOTE: This document is work in progress!

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

## cli\_shell

`cli\_shell` is a debug tool that writes (via an `ioctl()` call (TODO: fill in details))
the requested command to `/dev/cli`, which is writable by the `shell` group (i.e. via
`adb`). The command response is printed to the kernel log, which is not directly readable
by the shell user, but shows up in the Android log.

For instance, to get a help, run:
```
shell@PH7M_EU_1337:/ $ cli_shell help                                                               
sh: can't create /proc/sys/kernel/printk: Permission denied
sh: can't create /proc/sys/kernel/printk: Permission denied
shell@PH7M_EU_1337:/ $ logcat -d|sed '/.* MTK_KL[^:]*: /p;d'
[…]
01-22 20:05:14.398  1238  1238 D MTK_KL  : <4>[ 1196.054971] cd:                     Change current directory
01-22 20:05:14.398  1238  1238 D MTK_KL  : <4>[ 1196.054981] do:                     Repeat command
01-22 20:05:14.398  1238  1238 D MTK_KL  : <4>[ 1196.054986] alias(a):               Add/Show current alias
01-22 20:05:14.398  1238  1238 D MTK_KL  : <4>[ 1196.055025] ls:                     Recursive list all commands
[…]
```

Some useful commands:
* `b.ver`: Prints system information
* `r`: Read memory
* `w`: Write memory
