# wine20-bcrypt-doom
## Patched WINE bCrypt dll to run DOOM (2016)

### Wine-Staging realeased it's own implementation:
### https://github.com/wine-compholio/wine-staging/tree/master/patches/bcrypt-Improvements
### Consider using it instead of this workaround.



### This repo reimplements bCrypt using libgcrypt:
### https://github.com/isage/wine-doom


irc: freenode.net #doom-wine

### Vulkan support note
if you have vulkan available in your drivers, you can try it, but you will have to build wine-staging from
https://github.com/wine-compholio/wine-patched
instead of wine-2.0-rc1.

and don't forget to copy `wine-2.0-rc1/include/bcrypt.h` to `wine-patched/include/`

### Current progress:

Everything works now with current wine-staging implementation of bCrypt and fixes of winhttp.
No need to use this workaround.

### If you have any build errors - check the build dependencies.
on ubuntu libgnutls28-dev is required: https://github.com/thevoidnn/wine20-bcrypt-doom/issues/2

### How to build

First, create a directory, where you will build wine:
```
$ mkdir ~/wine20
$ cd ~/wine20
```

If you're on Arch Linux, you can run
```
$ yaourt -S wine-git
```
just to install all the build dependecies (but don't actually compile it or install this package!)
( you can see the dep list here https://aur.archlinux.org/packages/wine-git )

Then you have to get wine-2.0-rc1 sources from winehq ( https://www.winehq.org/news/2016120901 )
```
$ wget https://dl.winehq.org/wine/source/2.0/wine-2.0-rc1.tar.bz2
```

Then you need to extract wine sources
```
$ tar xf wine-2.0-rc1.tar.bz2
```

Get my patch
```
$ git clone https://github.com/thevoidnn/wine20-bcrypt-doom.git
```

Apply my patch
```
$ cp -r wine20-bcrypt-doom/* .
```

Then you have to build it...

If you're on Arch Linux - you can just run
```
$ ./build.sh
```

(But it's always a good idea to read it first)

Now grab some tea/coffee and just wait till the building is done.


I've also provided few ssh scripts to run steam and winecfg,
but you have to edit them first, because they have wine prefix path
which you probably don't have in your system.

To install Steam in your new wineprefix, you have to run

    $ WINEPREFIX="/path/to/your/new/wineprefix" ./wine-2.0-rc1-64-build/wine ~/Downloads/SteamSetup.exe

Don't forget to put the same wineprefix path in this scripts:

    $ $EDITOR ./winecfg.sh
    $ $EDITOR ./steam.sh
    $ $EDITOR ./steam-trace.sh

If you want the game to start in a window you can use `+set r_fullscreen 0`

Right click on DOOM in steam library -> Properties -> Set Launch Options:

    +set r_fullscreen 0


http://steamcommunity.com/app/379720/discussions/0/152391995402132325/
