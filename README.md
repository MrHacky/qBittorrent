qBittorrent - Improving Streaming support
------------------------------------------
********************************
##Description:
qBittorrent is a bittorrent client programmed in C++ / Qt that uses
libtorrent (sometimes called libtorrent-rasterbar) by Arvid Norberg.

This fork aims to improve streaming support. The main goal is to be
able to 'play' magnet: links on something like kodi. (Existing solutions
don't work for all torrents/media files)

##Warning:

This repository is not stable and history will be rewritten/rebased.
Authentication on the qBittorrent webinterface is disabled for debugging
purposes.

##Status:

A small number of additions to the webinterface have been made, the actual streaming
over http, with seeking support, is done by [torrent-streamer](https://github.com/MrHacky/torrent-streamer).

####libtorrent

Some changes have been made to libtorrent as well. Libtorrent needs to be
compiled with ./libtorrent.patch applied to it. (based on RC_0_16 branch).
The change allows is to combine sequential download with prioritizing of
specific pieces, which will download sequentially starting at those pieces.

