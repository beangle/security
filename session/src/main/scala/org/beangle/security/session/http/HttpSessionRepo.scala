package org.beangle.security.session.http

import java.net.{ HttpURLConnection, URL }

import org.beangle.cache.CacheManager
import org.beangle.commons.io.BinarySerializer
import org.beangle.commons.net.http.{ HttpMethods, HttpUtils }
import org.beangle.security.session.Session
import org.beangle.security.session.cache.CacheSessionRepo

class HttpSessionRepo(cacheManager: CacheManager, serializer: BinarySerializer)
    extends CacheSessionRepo(cacheManager) {

  var geturl: String = _
  var accessUrl: String = _

  protected def getInternal(sessionId: String): Option[Session] = {
    HttpUtils.getData(geturl.replace("{id}", sessionId)) map { data =>
      serializer.asObject(classOf[Session], data)
    }
  }

  def heartbeat(session: Session): Boolean = {
    var surl = accessUrl.replace("{id}", session.id)
    surl = surl.replace("{time}", session.lastAccessAt.getEpochSecond.toString)
    val url = new URL(surl)
    val hc = url.openConnection().asInstanceOf[HttpURLConnection]
    hc.setRequestMethod(HttpMethods.GET)
    hc.getResponseCode == 200
  }
}