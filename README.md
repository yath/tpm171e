# TPM171E

This page collects some technical information for the Philips (a.k.a. TPVision)
Android TV; specifically, for my 2018 65OLED803 series. Addresses may vary.

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

## cli\_shell

`cli_shell` is a debug tool that writes (via `ioctl(fd, 1, command_buffer)`)
the requested command to `/dev/cli`, which is writable by the `shell` group (i.e. via
`adb`). The command response is printed to the kernel log, which is not directly readable
by the shell user, but shows up in the Android log.

For instance, to get a help, run:
```
shell@PH7M_EU_1337:/ $ cli_shell help                                                               
sh: can't create /proc/sys/kernel/printk: Permission denied
sh: can't create /proc/sys/kernel/printk: Permission denied
shell@PH7M_EU_1337:/ $ logcat -d|sed 's/.* MTK_KL[^:]*: \(.*\)/\1/p;d'
[…]
<4>[ 1196.054971] cd:                     Change current directory
<4>[ 1196.054981] do:                     Repeat command
<4>[ 1196.054986] alias(a):               Add/Show current alias
<4>[ 1196.055025] ls:                     Recursive list all commands
[…]
```

Some useful commands:
* `b.ver`: Prints system information
* `r`: Read memory
* `w`: Write memory

### Obtaining addresses of `mtk\_mod`

`dtv_driver.ko` contains the code for the `/dev/cli` handlers. To obtain a stack trace and
code dump, run `adb logcat` in one window and `adb shell cli_shell r 0x0 0x10` in another,
causing a NULL dereference.

```
[ 5075.501468] [<bf38e598>] (_CmdMemRead+0x90/0xe0 [mtk_mod]) from [<bf0cf9d8>] (CLI_CmdList+0x44c/0x494 [mtk_mod])
[ 5075.502379] [<bf0cf9d8>] (CLI_CmdList+0x44c/0x494 [mtk_mod]) from [<bf0d0194>] (CLI_PromptParser+0x234/0x29c [mtk_mod])
[ 5075.503255] [<bf0d0194>] (CLI_PromptParser+0x234/0x29c [mtk_mod]) from [<bf0cee4c>] (CLI_Input+0xb4/0x2fc [mtk_mod])
[ 5075.504252] [<bf0cee4c>] (CLI_Input+0xb4/0x2fc [mtk_mod]) from [<bf3201a4>] (ThreadProc+0x9c/0xa0 [mtk_mod])
[ 5075.504842] [<c004da70>] (kthread+0xbc/0xc8) from [<c000e718>] (ret_from_fork+0x14/0x20)
```
