<!--
SPDX-FileCopyrightText: 2026 feiyehua
SPDX-License-Identifier: GPL-2.0-only
-->
# Troubleshoot
## I've messed up my ART, and my device now refuse to restore, even to the latest version.
This can be a little scary, because the screen flashes and dims slowly. But this is fixable.
0. If you have backed up your ART, restore it. Otherwise, follow the instructions bellow.
1. Enter DFU mode, and obtain a APTicket for the latest signing firmware. Personalize the RestoreSEP with the APTicket.
2. Boot into your Ramdisk, and ssh into your device. 
3. Run the following commands:
```
/usr/sbin/hdik -nomount ram://10240
newfs_hfs /dev/disk4
mount_hfs /dev/disk4 /mnt6
```
This creates a disk with write permission. 
1. `scp` your personalized RestoreSEP to the mountpoint, then run `/usr/libexec/seputil --restore /mnt6/path/to/RestoreSEP.img4`
2. Run `/usr/libexec/seputil --commit-hash`
3. Run `/usr/libexec/seputil --art get`, you should now see a brand new ART:
```
raw ART: 304802010030210203077ee10414d077cb6475818095860d8251147827747fd7288704000400310004206afe56b2c6200ceeb81763caf2511d3f6d7a8e6f2a2034831d4a5035c2c666a2
Successfully parsed ART:
counter: 491233
manifest hash (20 bytes): d077cb6475818095860d8251147827747fd72887
sleep hash absent
restore nonce absent
```
4. Restore your device again.

