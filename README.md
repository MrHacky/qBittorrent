qBittorrent - Improving Streaming support
------------------------------------------
********************************
##Description:
qBittorrent is a bittorrent client programmed in C++ / Qt that uses
libtorrent (sometimes called libtorrent-rasterbar) by Arvid Norberg.

This fork aims to improve streaming support. The main goal is to be
able to 'play' magnet: links on something like xbmc. (Existing solutions
don't work for all torrents/media files)

##Warning:

This repository is not stable and history will be rewritten/rebased.
Authentication on the qBittorrent webinterface is disabled for debugging
purposes.

##Status:

Mostly working, but with very hacky/ugly code.

##Details:

####libtorrent

Some changes have been made to libtorrent as well. Libtorrent needs to be
compiled with ./libtorrent.patch applied to it. (based on RC_0_16 branch).
The change allows is to combine sequential download with prioritizing of
specific pieces, which will download sequentially starting at those pieces.

####streaming with seeking

Using this, the qBitTorrent webserver is extended with a streaming interface
that allows seeking. Accessing /stream on the webserver will serve a file in
a torrent. The 'hash' url parameter should be the infohash of the torrent
you want, and the 'file' parameter should be the index of the file within
the torrent.

####torrent as playlist

Accessing /playlist/<MAGNETURL> ('/playlist/magnet:?....') will start
downloading the torrent specified by the magnet url, if it is not in the
list already. An .asx playlist will be return with an entry for each video
file in the torrent, with corresponding /stream urls.
