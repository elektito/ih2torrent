ih2torrent
==========

`ih2torrent` creates a trackerless torrent file from an infohash or a
magnet URI. It uses BitTorrent [DHT][1] and the [metadata protocol][2]
to find peers for the torrent and obtain its metadata.

In order to get the dependencies inside a virtualenv, run `make`. You
need Python 3.5 or higher to run ih2torrent.

You can use pip to install ih2torrent: `pip3 install ih2torrent`

[1]: http://www.bittorrent.org/beps/bep_0005.html
[2]: http://www.bittorrent.org/beps/bep_0009.html
