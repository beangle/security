package org.beangle.security.session.http

import java.net.{ HttpURLConnection, URL }

import org.beangle.cache.CacheManager
import org.beangle.commons.io.BinarySerializer
import org.beangle.commons.lang.Strings.replace
import org.beangle.commons.net.http.{ HttpMethods, HttpUtils }
import org.beangle.security.session.{ Session, DefaultSession}
import org.beangle.security.session.cache.CacheSessionRepo

class HttpSessionRepo(cacheManager: CacheManager, serializer: BinarySerializer)
    extends CacheSessionRepo(cacheManager) {

  var geturl: String = _
  var accessUrl: String = _

  protected def getInternal(sessionId: String): Option[Session] = {
    HttpUtils.getData(replace(geturl, "{id}", sessionId)) map { data =>
      serializer.asObject(classOf[DefaultSession], data)
    }
  }

  def heartbeat(session: Session): Boolean = {
    var surl = replace(accessUrl, "{id}", session.id)
    surl = replace(surl, "{time}", session.lastAccessAt.getEpochSecond.toString)
    val url = new URL(surl)
    val hc = url.openConnection().asInstanceOf[HttpURLConnection]
    hc.setRequestMethod(HttpMethods.GET)
    hc.getResponseCode == 200
  }
}
