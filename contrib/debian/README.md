
Debian
====================
This directory contains files used to package mmpcoind/mmpcoin-qt
for Debian-based Linux systems. If you compile mmpcoind/mmpcoin-qt yourself, there are some useful files here.

## mmpcoin: URI support ##


mmpcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install mmpcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your mmpcoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/mmpcoin128.png` to `/usr/share/pixmaps`

mmpcoin-qt.protocol (KDE)

