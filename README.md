ih2torrent
==========

`ih2torrent` creates a trackerless torrent file from an infohash. It
uses BitTorrent [DHT][1] and the [metadata protocol][2] to find peers for the
torrent and obtain its metadata.

In order to get the dependencies inside a virtualenv, run `make`. You
need Python 3.4.3 or higher to run ih2torrent. Notice that for some
reason when using Python 3.4.3, lots of "Exception" reports is printed
at the end of the program. This doesn't seem to have any negative
effect on the working of the program though. With Python 3.5 there
doesn't seem to be such a problem.

[1]: http://www.bittorrent.org/beps/bep_0005.html
[2]: http://www.bittorrent.org/beps/bep_0009.html
