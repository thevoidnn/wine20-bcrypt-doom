# wine20-bcrypt-doom
## Patched WINE bCrypt dll to run DOOM (2016)

### This whole library should be reimplemented using some crypto lib, which at least has a hash duplicating functionality.
### Current workaround is a crap, but it works :)

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

Currently, the game only runs with
    
    +set devMode_enable 1

Otherwise it will crash once it starts to communicate with bethesda servers.
You can prevent it from doing so by editing /etc/hosts and adding this lines,
but you probably should use devMode_enable 1 instead

    127.0.0.1 dfw-gobbler.doom.amok.systems
    127.0.0.1 services.bethesda.net


I would suggest setting `+set r_fullscreen 0` too:

Right click on DOOM in steam library -> Properties -> Set Launch Options:

    +set devMode_enable 1 +set r_fullscreen 0


http://steamcommunity.com/app/379720/discussions/0/152391995402132325/
