/*
 * Bittorrent Client using Qt4 and libtorrent.
 * Copyright (C) 2006  Ishan Arora and Christophe Dumez
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders give permission to
 * link this program with the OpenSSL project's "OpenSSL" library (or with
 * modified versions of it that use the same license as the "OpenSSL" library),
 * and distribute the linked executables. You must obey the GNU General Public
 * License in all respects for all of the code used other than "OpenSSL".  If you
 * modify file(s), you may extend this exception to your version of the file(s),
 * but you are not obligated to do so. If you do not wish to do so, delete this
 * exception statement from your version.
 *
 * Contact : chris@qbittorrent.org
 */


#include "httpconnection.h"
#include "httpserver.h"
#include "preferences.h"
#include "btjson.h"
#include "prefjson.h"
#include "qbtsession.h"
#include "misc.h"
#ifndef DISABLE_GUI
#include "iconprovider.h"
#endif
#include <QTcpSocket>
#include <QDateTime>
#include <QStringList>
#include <QHttpRequestHeader>
#include <QHttpResponseHeader>
#include <QFile>
#include <QDebug>
#include <QRegExp>
#include <QPainter>
#include <QBuffer>
#include <QTemporaryFile>
#include <QXmlStreamWriter>
#include <queue>
#include <vector>
#include <utility>

using namespace libtorrent;


struct media_entry {
    int index;
    QString title;
    QString extension;

    bool operator<(const media_entry& o) const
    {
        return title.toLower() < o.title.toLower();
    }
};

QList<media_entry> getMediaListFromTorrent(const QTorrentHandle& h);

HttpConnection::HttpConnection(QTcpSocket *socket, HttpServer *parent)
  : QObject(parent), m_socket(socket), m_httpserver(parent)
{
  m_socket->setParent(this);
  connect(m_socket, SIGNAL(readyRead()), SLOT(read()));
  connect(m_socket, SIGNAL(disconnected()), SLOT(deleteLater()));
}

HttpConnection::~HttpConnection() {
  delete m_socket;
}

void HttpConnection::processDownloadedFile(const QString &url,
                                           const QString &file_path) {
  qDebug("URL %s successfully downloaded !", qPrintable(url));
  emit torrentReadyToBeDownloaded(file_path, false, url, false);
}

void HttpConnection::handleDownloadFailure(const QString& url,
                                           const QString& reason) {
  std::cerr << "Could not download " << qPrintable(url) << ", reason: "
            << qPrintable(reason) << std::endl;
}

void HttpConnection::read()
{
  m_receivedData.append(m_socket->readAll());

  // Parse HTTP request header
  const int header_end = m_receivedData.indexOf("\r\n\r\n");
  if (header_end < 0) {
    qDebug() << "Partial request: \n" << m_receivedData;
    // Partial request waiting for the rest
    return;
  }

  const QByteArray header = m_receivedData.left(header_end);
  m_parser.writeHeader(header);
  if (m_parser.isError()) {
    qWarning() << Q_FUNC_INFO << "header parsing error";
    m_receivedData.clear();
    m_generator.setStatusLine(400, "Bad Request");
    m_generator.setContentEncoding(m_parser.acceptsEncoding());
    write();
    return;
  }

  // Parse HTTP request message
  if (m_parser.header().hasContentLength())  {
    const int expected_length = m_parser.header().contentLength();
    QByteArray message = m_receivedData.mid(header_end + 4, expected_length);

    if (expected_length > 10000000 /* ~10MB */) {
      qWarning() << "Bad request: message too long";
      m_generator.setStatusLine(400, "Bad Request");
      m_generator.setContentEncoding(m_parser.acceptsEncoding());
      m_receivedData.clear();
      write();
      return;
    }

    if (message.length() < expected_length) {
      // Message too short, waiting for the rest
      qDebug() << "Partial message:\n" << message;
      return;
    }

    m_parser.writeMessage(message);
    m_receivedData = m_receivedData.mid(header_end + 4 + expected_length);
  } else {
    m_receivedData.clear();
  }

  if (m_parser.isError()) {
    qWarning() << Q_FUNC_INFO << "message parsing error";
    m_generator.setStatusLine(400, "Bad Request");
    m_generator.setContentEncoding(m_parser.acceptsEncoding());
    write();
  } else {
    respond();
  }
}

void HttpConnection::write()
{
  m_socket->write(m_generator.toByteArray());
  m_socket->disconnectFromHost();
}

void HttpConnection::translateDocument(QString& data) {
  static QRegExp regex(QString::fromUtf8("_\\(([\\w\\s?!:\\/\\(\\),%µ&\\-\\.]+)\\)"));
  static QRegExp mnemonic("\\(?&([a-zA-Z]?\\))?");
  const std::string contexts[] = {"TransferListFiltersWidget", "TransferListWidget",
                                  "PropertiesWidget", "MainWindow", "HttpServer",
                                  "confirmDeletionDlg", "TrackerList", "TorrentFilesModel",
                                  "options_imp", "Preferences", "TrackersAdditionDlg",
                                  "ScanFoldersModel", "PropTabBar", "TorrentModel",
                                  "downloadFromURL", "misc"};
  const size_t context_count = sizeof(contexts)/sizeof(contexts[0]);
  int i = 0;
  bool found = true;

  const QString locale = Preferences().getLocale();
  bool isTranslationNeeded = !locale.startsWith("en") || locale.startsWith("en_AU") || locale.startsWith("en_GB");

  while(i < data.size() && found) {
    i = regex.indexIn(data, i);
    if (i >= 0) {
      //qDebug("Found translatable string: %s", regex.cap(1).toUtf8().data());
      QByteArray word = regex.cap(1).toUtf8();

      QString translation = word;
      if (isTranslationNeeded) {
        size_t context_index = 0;
        while(context_index < context_count && translation == word) {
          translation = qApp->translate(contexts[context_index].c_str(), word.constData(), 0, QCoreApplication::UnicodeUTF8, 1);
          ++context_index;
        }
      }
      // Remove keyboard shortcuts
      translation.replace(mnemonic, "");

      data.replace(i, regex.matchedLength(), translation);
      i += translation.length();
    } else {
        found = false; // no more translatable strings
    }
  }
}

void HttpConnection::write_partial()
{
  m_socket->write(m_generator.toString().toUtf8());
}

void HttpConnection::respond() {
  if ((m_socket->peerAddress() != QHostAddress::LocalHost
      && m_socket->peerAddress() != QHostAddress::LocalHostIPv6
      && false)
     || m_httpserver->isLocalAuthEnabled()) {
    // Authentication
    const QString peer_ip = m_socket->peerAddress().toString();
    const int nb_fail = m_httpserver->NbFailedAttemptsForIp(peer_ip);
    if (nb_fail >= MAX_AUTH_FAILED_ATTEMPTS) {
      m_generator.setStatusLine(403, "Forbidden");
      m_generator.setMessage(tr("Your IP address has been banned after too many failed authentication attempts."));
      m_generator.setContentType("text/plain; charset=utf-8");
      m_generator.setContentEncoding(m_parser.acceptsEncoding());
      write();
      return;
    }
    QString auth = m_parser.header().value("Authorization");
    if (auth.isEmpty()) {
      // Return unauthorized header
      qDebug("Auth is Empty...");
      m_generator.setStatusLine(401, "Unauthorized");
      m_generator.setValue("WWW-Authenticate",  "Digest realm=\""+QString(QBT_REALM)+"\", nonce=\""+m_httpserver->generateNonce()+"\", opaque=\""+m_httpserver->generateNonce()+"\", stale=\"false\", algorithm=\"MD5\", qop=\"auth\"");
      m_generator.setContentEncoding(m_parser.acceptsEncoding());
      write();
      return;
    }
    //qDebug("Auth: %s", qPrintable(auth.split(" ").first()));
    if (QString::compare(auth.split(" ").first(), "Digest", Qt::CaseInsensitive) != 0
        || !m_httpserver->isAuthorized(auth.toUtf8(), m_parser.header().method())) {
      // Update failed attempt counter
      m_httpserver->increaseNbFailedAttemptsForIp(peer_ip);
      qDebug("client IP: %s (%d failed attempts)", qPrintable(peer_ip), nb_fail);
      // Return unauthorized header
      m_generator.setStatusLine(401, "Unauthorized");
      m_generator.setValue("WWW-Authenticate",  "Digest realm=\""+QString(QBT_REALM)+"\", nonce=\""+m_httpserver->generateNonce()+"\", opaque=\""+m_httpserver->generateNonce()+"\", stale=\"false\", algorithm=\"MD5\", qop=\"auth\"");
      m_generator.setContentEncoding(m_parser.acceptsEncoding());
      write();
      return;
    }
    // Client successfully authenticated, reset number of failed attempts
    m_httpserver->resetNbFailedAttemptsForIp(peer_ip);
  }
  QString url  = m_parser.url();
  // Favicon
  if (url.endsWith("favicon.ico")) {
    qDebug("Returning favicon");
    QFile favicon(":/Icons/skin/qbittorrent16.png");
    if (favicon.open(QIODevice::ReadOnly)) {
      const QByteArray data = favicon.readAll();
      favicon.close();
      m_generator.setStatusLine(200, "OK");
      m_generator.setContentTypeByExt("png");
      m_generator.setMessage(data);
      m_generator.setContentEncoding(m_parser.acceptsEncoding());
      write();
    } else {
      respondNotFound();
    }
    return;
  }

  QStringList list = url.split('/', QString::SkipEmptyParts);
  if (list.contains(".") || list.contains("..")) {
    respondNotFound();
    return;
  }

  if (list.isEmpty())
    list.append("index.html");

  if (list.size() >= 2) {
    if (list[0] == "json") {
      if (list[1] == "torrents") {
        respondTorrentsJson();
        return;
      }
      if (list.size() > 2) {
        if (list[1] == "propertiesGeneral") {
          const QString& hash = list[2];
          respondGenPropertiesJson(hash);
          return;
        }
        if (list[1] == "propertiesTrackers") {
          const QString& hash = list[2];
          respondTrackersPropertiesJson(hash);
          return;
        }
        if (list[1] == "propertiesFiles") {
          const QString& hash = list[2];
          respondFilesPropertiesJson(hash);
          return;
        }
      } else {
        if (list[1] == "preferences") {
          respondPreferencesJson();
          return;
        } else {
          if (list[1] == "transferInfo") {
            respondGlobalTransferInfoJson();
            return;
          }
        }
      }
    }
    if (list[0] == "command") {
      const QString& command = list[1];
      if (command == "shutdown") {
        qDebug() << "Shutdown request from Web UI";
        // Special case handling for shutdown, we
        // need to reply to the Web UI before
        // actually shutting down.
        m_generator.setStatusLine(200, "OK");
        m_generator.setContentEncoding(m_parser.acceptsEncoding());
        write();
        qApp->processEvents();
        // Exit application
        qApp->exit();
      } else {
        respondCommand(command);
        m_generator.setStatusLine(200, "OK");
        m_generator.setContentEncoding(m_parser.acceptsEncoding());
        write();
      }
      return;
    }
  }

  [&](){};

  if (list[0] == "start") {
    QString murl = "magnet:?" + QUrl::fromEncoded(m_parser.header().path().replace("%3A", ":").toLatin1()).query();
    QString hash = m_parser.get("xt").replace("%3A", ":").mid(9); // urn:btih:

    if (hash.size() == 32) {
        QString newhash;
        QString alfa = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        QString hex  = "0123456789abcdef";
        size_t acc = 0;
        int bits = 0;
        hash = hash.toUpper();
        for (int i = 0; i < 32; ++i) {
            int val = alfa.indexOf(hash[i]);
            acc = (acc << 5) | val;
            bits += 5;
            while (bits >= 4) {
                int nibble = (acc >> (bits - 4)) & 0x0f;
                newhash += hex[nibble];
                bits -= 4;
            }
        }
        hash = newhash;
    }

    qWarning() << "download: " << murl;
    qWarning() << "hash: " << hash;
    emit MagnetReadyToBeDownloaded(murl);
    QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
    h.set_sequential_download(true);

    QString host = m_parser.header().value("Host");
    QString url  = "http://" + host + "/playlist" + "?starting=1&hash=" + hash;
    m_generator.setStatusLine(302, "Found");
    m_generator.setContentEncoding(m_parser.acceptsEncoding());
    m_generator.setValue("Location", url);
    m_generator.setMessage(QByteArray());
    write();
  }

#if 0
  if (false) {

    // redirect to starting playlist
    // "redir.playlist": redirect to playlist
    // "open.playlist": tell xbmc to open playlist

    QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
    if (!h.is_valid()) {
        qWarning() << "download";
        emit MagnetReadyToBeDownloaded(url);
        h = QBtSession::instance()->getTorrentHandle(hash);
    }
    if (h.is_valid()) {
        qWarning() << "setseq";
        h.set_sequential_download(true);
    }
    if (!h.is_valid() || !h.has_metadata()) {
        qWarning() << "timer:" << (h.is_valid() ? 1000 : 10);
        QTimer* timer = new QTimer(this);
        connect(timer, SIGNAL(timeout()), this, SLOT(respond()));
        timer->setInterval(h.is_valid() ? 1000 : 10);
        timer->setSingleShot(true);
        timer->start();
        return;
    }

    if (type == "open.playlist") {
        static QDateTime lastopen = QDateTime(QDate(0, 0, 0), QTime(0, 0));
        QDateTime now = QDateTime::currentDateTime();
        if (lastopen.secsTo(now) > 15) {
            lastopen = now;
            QString host = m_parser.header().value("Host");
            QString url  = "http://" + host + "/playlist" + "?hash=" + hash;
            doXbmcJsonRequest(QString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"Player.Open\",\"params\":{\"item\":{\"file\":\"" + url + "\"}}}").toUtf8(), false);
        }
        m_generator.setStatusLine(302, "Found");
        m_generator.setContentEncoding(m_parser.acceptsEncoding());
        m_generator.setValue("Location", "/loading/?hash=" + hash);
        m_generator.setMessage(QByteArray());
        write();
    } else if (type == "redir.playlist") {
        QString host = m_parser.header().value("Host");
        QString url  = "http://" + host + "/playlist" + "?hash=" + hash;
        m_generator.setStatusLine(302, "Found");
        m_generator.setContentEncoding(m_parser.acceptsEncoding());
        m_generator.setValue("Location", url);
        m_generator.setMessage(QByteArray());
        write();
    } else {
      qWarning() << "unhandled type: " << type;
      respondNotFound();
    }
    return;

  }
#endif

  if (list[0] == "playlist") {
    QString hash = m_parser.get("hash");
    QString host = m_parser.header().value("Host");
    bool starting = m_parser.get("starting") == "1";

    QByteArray msg;
    QXmlStreamWriter stream(&msg);
    stream.setAutoFormatting(true);
    stream.writeStartDocument();
    stream.writeStartElement("asx");
    stream.writeAttribute("version", "3.0");

    if (starting) {
        stream.writeStartElement("entry");
        stream.writeTextElement("title", "Loading...");
        stream.writeStartElement("ref");
        stream.writeAttribute("href", "http://" + host + "/loading" + "?hash=" + hash + "&starting=1&maxticks=30");
        stream.writeEndElement(); // ref
        stream.writeEndElement(); // entry

        stream.writeStartElement("entry");
        stream.writeTextElement("title", "Playlist");
        stream.writeStartElement("ref");
        stream.writeAttribute("href", "http://" + host + "/playlist" + "?hash=" + hash);
        stream.writeEndElement(); // ref
        stream.writeEndElement(); // entry
    } else {
        QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
        if (!h.is_valid() || !h.has_metadata()) {
          respondNotFound();
          return;
        }
        qWarning() << "playlist";

        QList<media_entry> media = getMediaListFromTorrent(h);

        if (media.size() == 0) {
            respondNotFound();
        } else if (false && media.size() == 1) {
            m_generator.setStatusLine(302, "Found");
            m_generator.setContentEncoding(m_parser.acceptsEncoding());
            m_generator.setValue("Location", "/stream/tor." + media[0].extension + "?hash=" + hash + "&file=" + QString::number(media[0].index));
            m_generator.setMessage(QByteArray());
            write();
        } else {
            for (int i = 0; i < media.size(); ++i) {
                stream.writeStartElement("entry");
                stream.writeTextElement("title", media[i].title);
                stream.writeStartElement("ref");
                stream.writeAttribute("href", "http://" + host + "/stream/" + QUrl::toPercentEncoding(media[i].title) + "?hash=" + hash + "&file=" + QString::number(media[i].index));
                stream.writeEndElement(); // ref
                stream.writeEndElement(); // entry
            }

            stream.writeStartElement("entry");
            stream.writeTextElement("title", "Done...");
            stream.writeStartElement("ref");
            stream.writeAttribute("href", "http://" + host + "/loading/done" + "?hash=" + hash);
            stream.writeEndElement(); // ref
            stream.writeEndElement(); // entry
        }
    }

    stream.writeEndElement(); // asx
    stream.writeEndDocument();

    m_generator.setStatusLine(200, "OK");
    if (m_parser.get("noct") != "1" || m_parser.header().value("User-Agent").toStdString().find("Chrome") == std::string::npos)
        m_generator.setContentType("video/x-ms-asf");
    m_generator.setMessage(msg);
    m_generator.setContentEncoding(m_parser.acceptsEncoding());
    write();

    return;
  }

  if (list[0] == "stream") {
      new HttpTorrentConnection(this);
      return;
  }

  if (list[0] == "loading") {
      new HttpLoadingConnection(this);
      return;
  }

  // Icons from theme
  //qDebug() << "list[0]" << list[0];
  if (list[0] == "theme" && list.size() == 2) {
#ifdef DISABLE_GUI
    url = ":/Icons/oxygen/"+list[1]+".png";
#else
    url = IconProvider::instance()->getIconPath(list[1]);
#endif
    qDebug() << "There icon:" << url;
  } else {
    if (list[0] == "images") {
      list[0] = "Icons";
    } else {
      if (list.last().endsWith(".html"))
        list.prepend("html");
      list.prepend("webui");
    }
    url = ":/" + list.join("/");
  }
  QFile file(url);
  if (!file.open(QIODevice::ReadOnly)) {
    qDebug("File %s was not found!", qPrintable(url));
    respondNotFound();
    return;
  }
  QString ext = list.last();
  int index = ext.lastIndexOf('.') + 1;
  if (index > 0)
    ext.remove(0, index);
  else
    ext.clear();
  QByteArray data = file.readAll();
  file.close();

  // Translate the page
  if (ext == "html" || (ext == "js" && !list.last().startsWith("excanvas"))) {
    QString dataStr = QString::fromUtf8(data.constData());
    translateDocument(dataStr);
    if (url.endsWith("about.html")) {
      dataStr.replace("${VERSION}", VERSION);
    }
    data = dataStr.toUtf8();
  }
  m_generator.setStatusLine(200, "OK");
  m_generator.setContentTypeByExt(ext);
  m_generator.setMessage(data);
  m_generator.setContentEncoding(m_parser.acceptsEncoding());
  write();
}

void HttpConnection::respondNotFound() {
  m_generator.setStatusLine(404, "File not found");
  m_generator.setContentEncoding(m_parser.acceptsEncoding());
  write();
}

void HttpConnection::respondTorrentsJson() {
  m_generator.setStatusLine(200, "OK");
  m_generator.setContentTypeByExt("js");
  m_generator.setMessage(btjson::getTorrents());
  m_generator.setContentEncoding(m_parser.acceptsEncoding());
  write();
}

void HttpConnection::respondGenPropertiesJson(const QString& hash) {
  m_generator.setStatusLine(200, "OK");
  m_generator.setContentTypeByExt("js");
  m_generator.setMessage(btjson::getPropertiesForTorrent(hash));
  m_generator.setContentEncoding(m_parser.acceptsEncoding());
  write();
}

void HttpConnection::respondTrackersPropertiesJson(const QString& hash) {
  m_generator.setStatusLine(200, "OK");
  m_generator.setContentTypeByExt("js");
  m_generator.setMessage(btjson::getTrackersForTorrent(hash));
  m_generator.setContentEncoding(m_parser.acceptsEncoding());
  write();
}

void HttpConnection::respondFilesPropertiesJson(const QString& hash) {
  m_generator.setStatusLine(200, "OK");
  m_generator.setContentTypeByExt("js");
  m_generator.setMessage(btjson::getFilesForTorrent(hash));
  m_generator.setContentEncoding(m_parser.acceptsEncoding());
  write();
}

void HttpConnection::respondPreferencesJson() {
  m_generator.setStatusLine(200, "OK");
  m_generator.setContentTypeByExt("js");
  m_generator.setMessage(prefjson::getPreferences());
  m_generator.setContentEncoding(m_parser.acceptsEncoding());
  write();
}

void HttpConnection::respondGlobalTransferInfoJson() {
  m_generator.setStatusLine(200, "OK");
  m_generator.setContentTypeByExt("js");
  m_generator.setMessage(btjson::getTransferInfo());
  m_generator.setContentEncoding(m_parser.acceptsEncoding());
  write();
}

void HttpConnection::respondCommand(const QString& command) {
  qDebug() << Q_FUNC_INFO << command;
  if (command == "download") {
    QString urls = m_parser.post("urls");
    QStringList list = urls.split('\n');
    foreach (QString url, list) {
      url = url.trimmed();
      if (!url.isEmpty()) {
        if (url.startsWith("bc://bt/", Qt::CaseInsensitive)) {
          qDebug("Converting bc link to magnet link");
          url = misc::bcLinkToMagnet(url);
        }
        if (url.startsWith("magnet:", Qt::CaseInsensitive)) {
          emit MagnetReadyToBeDownloaded(url);
        } else {
          qDebug("Downloading url: %s", qPrintable(url));
          emit UrlReadyToBeDownloaded(url);
        }
      }
    }
    return;
  }

  if (command == "addTrackers") {
    QString hash = m_parser.post("hash");
    if (!hash.isEmpty()) {
      QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
      if (h.is_valid() && h.has_metadata()) {
        QString urls = m_parser.post("urls");
        QStringList list = urls.split('\n');
        foreach (const QString& url, list) {
          announce_entry e(url.toStdString());
          h.add_tracker(e);
        }
      }
    }
    return;
  }
  if (command == "upload") {
    qDebug() << Q_FUNC_INFO << "upload";
    const QList<QByteArray>& torrents = m_parser.torrents();
    foreach(const QByteArray& torrentContent, torrents) {
      // Get a unique filename
      QTemporaryFile *tmpfile = new QTemporaryFile(QDir::temp().absoluteFilePath("qBT-XXXXXX.torrent"));
      tmpfile->setAutoRemove(false);
      if (tmpfile->open()) {
        QString filePath = tmpfile->fileName();
        tmpfile->write(torrentContent);
        tmpfile->close();
        // XXX: tmpfile needs to be deleted on Windows before using the file
        // or it will complain that the file is used by another process.
        delete tmpfile;
        emit torrentReadyToBeDownloaded(filePath, false, QString(), false);
        // Clean up
        fsutils::forceRemove(filePath);
      } else {
        std::cerr << "I/O Error: Could not create temporary file" << std::endl;
        delete tmpfile;
        return;
      }
    }
    // Prepare response
    m_generator.setStatusLine(200, "OK");
    m_generator.setContentTypeByExt("html");
    m_generator.setMessage(QString("<script type=\"text/javascript\">window.parent.hideAll();</script>"));
    m_generator.setContentEncoding(m_parser.acceptsEncoding());
    write();
    return;
  }
  if (command == "resumeall") {
    emit resumeAllTorrents();
    return;
  }
  if (command == "pauseall") {
    emit pauseAllTorrents();
    return;
  }
  if (command == "resume") {
    emit resumeTorrent(m_parser.post("hash"));
    return;
  }
  if (command == "setPreferences") {
    prefjson::setPreferences(m_parser.post("json"));
    return;
  }
  if (command == "setFilePrio") {
    QString hash = m_parser.post("hash");
    int file_id = m_parser.post("id").toInt();
    int priority = m_parser.post("priority").toInt();
    QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
    if (h.is_valid() && h.has_metadata()) {
      h.file_priority(file_id, priority);
    }
    return;
  }
  if (command == "getGlobalUpLimit") {
    m_generator.setStatusLine(200, "OK");
    m_generator.setContentTypeByExt("html");
#if LIBTORRENT_VERSION_NUM >= 1600
    m_generator.setMessage(QByteArray::number(QBtSession::instance()->getSession()->settings().upload_rate_limit));
#else
    m_generator.setMessage(QByteArray::number(QBtSession::instance()->getSession()->upload_rate_limit()));
#endif
    m_generator.setContentEncoding(m_parser.acceptsEncoding());
    write();
    return;
  }
  if (command == "getGlobalDlLimit") {
    m_generator.setStatusLine(200, "OK");
    m_generator.setContentTypeByExt("html");
#if LIBTORRENT_VERSION_NUM >= 1600
    m_generator.setMessage(QByteArray::number(QBtSession::instance()->getSession()->settings().download_rate_limit));
#else
    m_generator.setMessage(QByteArray::number(QBtSession::instance()->getSession()->download_rate_limit()));
#endif
    m_generator.setContentEncoding(m_parser.acceptsEncoding());
    write();
    return;
  }
  if (command == "getTorrentUpLimit") {
    QString hash = m_parser.post("hash");
    QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
    if (h.is_valid()) {
      m_generator.setStatusLine(200, "OK");
      m_generator.setContentTypeByExt("html");
      m_generator.setMessage(QByteArray::number(h.upload_limit()));
      m_generator.setContentEncoding(m_parser.acceptsEncoding());
      write();
    }
    return;
  }
  if (command == "getTorrentDlLimit") {
    QString hash = m_parser.post("hash");
    QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
    if (h.is_valid()) {
      m_generator.setStatusLine(200, "OK");
      m_generator.setContentTypeByExt("html");
      m_generator.setMessage(QByteArray::number(h.download_limit()));
      m_generator.setContentEncoding(m_parser.acceptsEncoding());
      write();
    }
    return;
  }
  if (command == "setTorrentUpLimit") {
    QString hash = m_parser.post("hash");
    qlonglong limit = m_parser.post("limit").toLongLong();
    if (limit == 0) limit = -1;
    QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
    if (h.is_valid()) {
      h.set_upload_limit(limit);
    }
    return;
  }
  if (command == "setTorrentDlLimit") {
    QString hash = m_parser.post("hash");
    qlonglong limit = m_parser.post("limit").toLongLong();
    if (limit == 0) limit = -1;
    QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
    if (h.is_valid()) {
      h.set_download_limit(limit);
    }
    return;
  }
  if (command == "setGlobalUpLimit") {
    qlonglong limit = m_parser.post("limit").toLongLong();
    if (limit == 0) limit = -1;
    QBtSession::instance()->setUploadRateLimit(limit);
    Preferences().setGlobalUploadLimit(limit/1024.);
    return;
  }
  if (command == "setGlobalDlLimit") {
    qlonglong limit = m_parser.post("limit").toLongLong();
    if (limit == 0) limit = -1;
    QBtSession::instance()->setDownloadRateLimit(limit);
    Preferences().setGlobalDownloadLimit(limit/1024.);
    return;
  }
  if (command == "pause") {
    emit pauseTorrent(m_parser.post("hash"));
    return;
  }
  if (command == "delete") {
    QStringList hashes = m_parser.post("hashes").split("|");
    foreach (const QString &hash, hashes) {
      emit deleteTorrent(hash, false);
    }
    return;
  }
  if (command == "deletePerm") {
    QStringList hashes = m_parser.post("hashes").split("|");
    foreach (const QString &hash, hashes) {
      emit deleteTorrent(hash, true);
    }
    return;
  }
  if (command == "increasePrio") {
    increaseTorrentsPriority(m_parser.post("hashes").split("|"));
    return;
  }
  if (command == "decreasePrio") {
    decreaseTorrentsPriority(m_parser.post("hashes").split("|"));
    return;
  }
  if (command == "topPrio") {
    foreach (const QString &hash, m_parser.post("hashes").split("|")) {
      QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
      if (h.is_valid()) h.queue_position_top();
    }
    return;
  }
  if (command == "bottomPrio") {
    foreach (const QString &hash, m_parser.post("hashes").split("|")) {
      QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
      if (h.is_valid()) h.queue_position_bottom();
    }
    return;
  }
  if (command == "recheck") {
    QBtSession::instance()->recheckTorrent(m_parser.post("hash"));
    return;
  }
}

void HttpConnection::decreaseTorrentsPriority(const QStringList &hashes) {
  qDebug() << Q_FUNC_INFO << hashes;
  std::priority_queue<QPair<int, QTorrentHandle>,
      std::vector<QPair<int, QTorrentHandle> >,
      std::less<QPair<int, QTorrentHandle> > > torrent_queue;
  // Sort torrents by priority
  foreach (const QString &hash, hashes) {
    try {
      QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
      if (!h.is_seed()) {
        torrent_queue.push(qMakePair(h.queue_position(), h));
      }
    }catch(invalid_handle&) {}
  }
  // Decrease torrents priority (starting with the ones with lowest priority)
  while(!torrent_queue.empty()) {
    QTorrentHandle h = torrent_queue.top().second;
    try {
      h.queue_position_down();
    } catch(invalid_handle& h) {}
    torrent_queue.pop();
  }
}

void HttpConnection::increaseTorrentsPriority(const QStringList &hashes)
{
  qDebug() << Q_FUNC_INFO << hashes;
  std::priority_queue<QPair<int, QTorrentHandle>,
      std::vector<QPair<int, QTorrentHandle> >,
      std::greater<QPair<int, QTorrentHandle> > > torrent_queue;
  // Sort torrents by priority
  foreach (const QString &hash, hashes) {
    try {
      QTorrentHandle h = QBtSession::instance()->getTorrentHandle(hash);
      if (!h.is_seed()) {
        torrent_queue.push(qMakePair(h.queue_position(), h));
      }
    }catch(invalid_handle&) {}
  }
  // Increase torrents priority (starting with the ones with highest priority)
  while(!torrent_queue.empty()) {
    QTorrentHandle h = torrent_queue.top().second;
    try {
      h.queue_position_up();
    } catch(invalid_handle& h) {}
    torrent_queue.pop();
  }
}

QByteArray HttpConnection::doXbmcJsonRequest(QByteArray req, bool wait_for_response)
{
    QTcpSocket* sock = new QTcpSocket(this);
    sock->connectToHost(m_socket->peerAddress(), 9090);
    qWarning() << "xbmc connect: " << sock->waitForConnected(1000);
    sock->write(req);
    if (!wait_for_response)
        return QByteArray();
    qWarning() << "xbmc write: " << sock->waitForBytesWritten(1000);
    qWarning() << "xbmc read: " << sock->waitForReadyRead(1000);
    QByteArray resp = sock->readAll();
    sock->close();
    return resp;
}

HttpTorrentConnection::HttpTorrentConnection(HttpConnection *parent)
  : QObject(parent), m_connection(parent), blocking_piece(-1)
{
    qWarning() << "Request------------:";

    // Get url params/header
    m_hash = m_connection->m_parser.get("hash");
    QString fnum = m_connection->m_parser.get("file");
    QString range = m_connection->m_parser.header().value("Range");

    qWarning() << "req_range: " << range;

    // validate 'hash'
    QTorrentHandle h = QBtSession::instance()->getTorrentHandle(m_hash);
    if (!h.is_valid() || !h.has_metadata()) {
        write_error(404, "Torrent or metadata not found.");
        return;
    }

    #if LIBTORRENT_VERSION_NUM < 10000
        torrent_info const* tf = &h.get_torrent_info();
    #else
        boost::intrusive_ptr<torrent_info const> tf = h.torrent_file();
    #endif
    const torrent_info& t = *tf;

    bool fidx_ok = false;
    int fidx = fnum.toInt(&fidx_ok);

    // validate 'file'
    if (!fidx_ok || fidx < 0 || fidx >= t.num_files()) {
        write_error(400, "Invalid file index in torrent.");
        return;
    }
    const file_entry& file = t.file_at(fidx);

    req_start = 0;
    req_end = file.size;
    // validate 'range'
    if (range != "") {
        QRegExp rxrange("^bytes=([0-9]*)-([0-9]*)$");
        if (rxrange.indexIn(range) != -1) {
            if (rxrange.cap(1) != "")
                req_start = rxrange.cap(1).toULongLong();
            if (rxrange.cap(2) != "")
                req_end = rxrange.cap(2).toULongLong() + 1;
            m_connection->m_generator.setStatusLine(206, "OK");
            m_connection->m_generator.setValue("Content-Range", "bytes " + QString::number(req_start) + '-' + QString::number(req_end - 1) + '/' + QString::number(file.size));
        } else {
            write_error(400, "Invalid range request.");
            return;
        }
    } else
        m_connection->m_generator.setStatusLine(200, "OK");

    h.set_sequential_download(true);

    m_connection->m_generator.setContentLength(req_end - req_start);
    m_connection->m_generator.setValue("Accept-Ranges", "bytes");
    m_connection->m_generator.setMessage(QByteArray());
    m_connection->write_partial();

    file_path = h.absolute_files_path()[fidx];
    file_offset = file.offset;
    file_size = file.size;
    num_pieces = t.num_pieces();
    piece_size = t.piece_length();

    qWarning() << "req_start: " << req_start;
    qWarning() << "req_end: " << req_end;

    QTimer* timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(timer_tick()));
    timer->setInterval(1000);
    timer->start();
    timer_tick();
}

void HttpTorrentConnection::timer_tick()
{
  quint64 btw = m_connection->m_socket->bytesToWrite();
  std::swap(bytes_to_write, btw);
  if (bytes_to_write > 64*1024) {
    if (bytes_to_write == btw) {
        qWarning() << "stalled: [" << nodrain << "] " << bytes_to_write;
        if (++nodrain > 10) // more than ten seconds without drainage
            release_priority();
        if (nodrain > 60) {
            m_connection->m_socket->disconnectFromHost();
            m_connection->m_socket->close();
            m_connection->deleteLater();
        }
    } else
        nodrain = 0;
  }

  if (bytes_to_write > 10*1000*1000)
      return;
  quint64 max_len = 11*1000*1000 - bytes_to_write;

  qWarning() << "timer tick!";
  qWarning() << "req_start: " << req_start;

  QTorrentHandle h = QBtSession::instance()->getTorrentHandle(m_hash);

  // Determine the first and last piece of the file
  quint64 req_piece = floor((file_offset + req_start + 1) / (float) piece_size);
  Q_ASSERT(req_piece >= 0 && req_piece < num_pieces);
  quint64 req_offset =  ((req_piece+1) * piece_size) - (file_offset + req_start);
  req_offset = piece_size - req_offset;
  quint64 max_len_pieces = 0;
  quint64 cp = req_piece;
  for (; cp < num_pieces && h.have_piece(cp); ++cp)
    max_len_pieces += piece_size;
  qWarning() << "piece_start: " << req_piece;
  qWarning() << "piece_missing: " << cp;

  if (max_len_pieces != 0)
    max_len_pieces -= req_offset;
  max_len = std::min(max_len, max_len_pieces);
  max_len = std::min(max_len, req_end - req_start);

  if (req_piece < num_pieces)
    acquire_priority(req_piece);
  if (max_len == 0)
    return;

  h.flush_cache();

  QByteArray data;
  QFile qf(file_path);
  if (qf.open(QIODevice::ReadOnly)) {
    qf.seek(req_start);
    data = qf.read(max_len);
  };
  //qWarning() << "max_len  : " << max_len;
  req_start += data.size();
  quint64 w = m_connection->m_socket->write(data);
  qWarning() << "data_write : " << w;

  if (w != data.size() || req_start >= req_end)
    m_connection->m_socket->disconnectFromHost();
}

void HttpTorrentConnection::write_error(int code, QString message)
{
    m_connection->m_generator.setStatusLine(code, message);
    m_connection->m_generator.setContentEncoding(m_connection->m_parser.acceptsEncoding());
    m_connection->write();
}

void HttpTorrentConnection::acquire_priority(int piece)
{
    if (piece != blocking_piece) {
        release_priority();
        blocking_piece = piece;

        QBtSession::instance()->getTorrentHandle(m_hash).piece_priority(blocking_piece, 7);
        qWarning() << "acq_prio: " << blocking_piece;
    }
}

void HttpTorrentConnection::release_priority()
{
    if (blocking_piece != -1) {
        QBtSession::instance()->getTorrentHandle(m_hash).piece_priority(blocking_piece, 1);
        qWarning() << "rel_prio: " << blocking_piece;
        blocking_piece = -1;
    }
}

HttpTorrentConnection::~HttpTorrentConnection()
{
    release_priority();
}

HttpLoadingConnection::HttpLoadingConnection(HttpConnection *parent)
  : QObject(parent), m_connection(parent)
{
    m_hash = m_connection->m_parser.get("hash");

    QString maxticks = m_connection->m_parser.get("maxticks");
    if (maxticks != "")
        m_maxticks = maxticks.toInt();

    HttpResponseHeader resp;
    m_boundary = "boundarydonotcross";

    //m_connection->m_generator.setContentLength(req_end - req_start);
    resp.setStatusLine(200, "OK");
    resp.setValue("Connection", "close");
    resp.setContentType("multipart/x-mixed-replace;boundary=" + m_boundary);
    //m_connection->m_generator.setMessage(QByteArray());
    m_connection->m_socket->write(resp.toString().toUtf8());

  qWarning() << "stream start";

    timer_tick();
    {
        QTimer* timer = new QTimer(this);
        connect(timer, SIGNAL(timeout()), this, SLOT(timer_tick()));
        timer->setInterval(1000 / 2);
        timer->start();
    }
    {
        QTimer* timer = new QTimer(this);
        connect(timer, SIGNAL(timeout()), this, SLOT(frame_tick()));
        timer->setInterval(1000 / 25);
        timer->start();
    }
}

void HttpLoadingConnection::write_error(int code, QString message)
{
    m_connection->m_generator.setStatusLine(code, message);
    m_connection->m_generator.setContentEncoding(m_connection->m_parser.acceptsEncoding());
    m_connection->write();
}

void HttpLoadingConnection::timer_tick()
{
    //qWarning() << "maxticks: " << m_maxticks;
    if (m_maxticks == 0) {
	  qWarning() << "stream stop";
        m_framedata = QByteArray();
        m_connection->m_socket->write(QString("--" + m_boundary + "--").toUtf8());
        /*
        m_connection->m_socket->disconnectFromHost();
        if (m_connection->m_socket->state() == QAbstractSocket::UnconnectedState || m_connection->m_socket->waitForDisconnected(5000))
            qWarning() << "Disconnected";
        else
            qWarning() << "Disconnect Failed!";
        return;
        */
        m_maxticks = -2;
        return;
        QString str = m_connection->doXbmcJsonRequest("{\"jsonrpc\": \"2.0\", \"method\": \"Player.GetActivePlayers\", \"params\": [], \"id\": 1})", true);
        QRegExp rx("\"playerid\"\\w*:\\w*([0-9]*)");
        if (rx.indexIn(str, 0) != -1) {
            QString playerid = rx.cap(1);
            qWarning() << "playerid: " << playerid;
            m_connection->doXbmcJsonRequest(QString("{\"jsonrpc\": \"2.0\", \"method\": \"Player.GoTo\", \"params\": [" +playerid +",\"next\"], \"id\": 2})").toUtf8(), false);
            m_maxticks = -2;
        } else
            qWarning() << "response: " << str;
    } else if (m_maxticks > 0)
        --m_maxticks;
    else if (m_maxticks < -1)
        return;

    int resdiv = 4;
    //QImage img(500, 250, QImage::Format_RGB32);
    QImage img(1920 / resdiv, 1080 / resdiv, QImage::Format_RGB32);
    {
        QTorrentHandle h = QBtSession::instance()->getTorrentHandle(m_hash);
        QString output = QString::number(m_maxticks / 2.0) + "\t" + QTime::currentTime().toString();
        if (h.is_valid() && h.has_metadata()) {
            #if LIBTORRENT_VERSION_NUM < 10000
                torrent_info const* tf = &h.get_torrent_info();
            #else
                boost::intrusive_ptr<torrent_info const> tf = h.torrent_file();
            #endif
            const torrent_info& t = *tf;

            qint64 piece_size = t.piece_length();
            qint64 req_start = 0;
            qint64 num_pieces = h.num_pieces();

            double maxpercent = 0;
            libtorrent::torrent_status status = h.status(torrent_handle::query_accurate_download_counters);
            output += "\t" + misc::friendlyUnit(status.download_payload_rate, true) + "\r\n";

            std::vector<libtorrent::size_type> progress;
            h.file_progress(progress);
            QList<media_entry> media = getMediaListFromTorrent(h);
            for (int j = 0; j < media.size(); ++j) {
                int i = media[j].index;
                QString fileName = media[j].title;

                const file_entry& file = t.file_at(i);
                qint64 file_offset = file.offset;
                qint64 file_size = file.size;

                qint64 req_piece = floor((file_offset + req_start + 1) / (float) piece_size);
                Q_ASSERT(req_piece >= 0 && req_piece < num_pieces);
                qint64 req_offset =  ((req_piece+1) * piece_size) - (file_offset + req_start);
                req_offset = piece_size - req_offset;
                qint64 max_len_pieces = -req_offset;
                qint64 cp = req_piece;
                for (; cp < num_pieces && h.have_piece(cp) && max_len_pieces < file_size; ++cp)
                  max_len_pieces += piece_size;
                if (max_len_pieces <= 0)
                    max_len_pieces = 0;
                if (max_len_pieces > file_size)
                    max_len_pieces = file_size;
                QString s;
                double pct = 100.0 * max_len_pieces / file_size;
                maxpercent = std::max(maxpercent, pct);
                s.sprintf("%.1f%%\t", pct);
                output += s;
                s.sprintf("%.1f%%\t", 100.0 * progress[i] / file_size);
                output += s;
                output += fsutils::fileName(fileName) + "\r\n";

                if (j == 0 && m_maxticks >= 3) {
                    if (pct < 0.5 && status.download_payload_rate < (1024*1024))
                        ++m_maxticks;
                    else
                        m_maxticks = 3;
                }
            }

            // wait until we have at least 2.5 percent of a file before we count down the last 5 seconds
            //if (m_maxticks >= 0 && m_maxticks < 10 && maxpercent < 2.5)
            //    ++m_maxticks;
        } else {
            //if (m_maxticks >= 0 && m_maxticks < 10 && maxpercent < 2.5)
            //    ++m_maxticks;
            output += "\r\nWaiting for metadata...\r\n";
            if (m_maxticks >= 0)
                ++m_maxticks;
        }

        QPainter pnt(&img);
        QRect r1(QPoint(), img.size());
        QRect r2(r1.left() + (20 / resdiv), r1.top() + (20 / resdiv), r1.width() - (40 / resdiv), r1.height() - (40 / resdiv));

        pnt.fillRect(r1, QColor(0, 0, 0));

        pnt.setPen(QColor(255, 255, 255));
        pnt.setFont(QFont("", 40 / resdiv));
        pnt.drawText(r2, Qt::TextExpandTabs, output);
    }
    QByteArray ba;
    {
        QBuffer buf(&ba);
        buf.open(QIODevice::WriteOnly);
        img.save(&buf, "JPEG", 50);
    }
    QByteArray hdr = QString(QString()
        + "Content-Type: image/jpeg\r\n"
        + "Content-Length: " + QString::number(ba.size()) + "\r\n"
        + "\r\n"
    ).toUtf8();

    //qWarning() << "jpeg size: " << ba.size();

    m_framedata = QByteArray();
    m_framedata += QString("--" + m_boundary + "\r\n").toUtf8();
    m_framedata += hdr;
    m_framedata += ba;
    m_framedata += "\r\n";
}

void HttpLoadingConnection::frame_tick()
{
    if (m_framedata.size() > 0) {
        m_connection->m_socket->write(m_framedata);
    } else {
        qint64 btw = m_connection->m_socket->bytesToWrite();
        qWarning() << "btw: " << btw;
        m_connection->m_socket->waitForBytesWritten(500);
        if (btw == 0) {
            m_connection->m_socket->waitForDisconnected(1000);
            m_connection->m_socket->close();
        }
    }
}

QList<media_entry> getMediaListFromTorrent(const QTorrentHandle& h)
{
    QList<media_entry> media;
    unsigned int nbFiles = h.num_files();
    for (unsigned int i=0; i<nbFiles; ++i) {
      QString fileName = h.filename_at(i);
      //qWarning() << "File:" << fileName;
      if (fileName.endsWith(".!qB"))
        fileName.chop(4);
      QString extension = fsutils::fileExtension(fileName).toUpper();

      if (misc::isPreviewable(extension) && fsutils::fileName(fileName) != "sample") {
          media << media_entry { i, fsutils::fileName(fileName), extension.toLower() };
      }
    }
    std::sort(media.begin(), media.end());
    return media;
}
