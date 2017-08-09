package org.beangle.security.session.http

import org.beangle.cache.CacheManager
import org.beangle.security.session.Session
import org.beangle.security.session.cache.CacheSessionRepo
import org.beangle.commons.net.http.HttpUtils
import java.net.HttpURLConnection
import java.net.URL
import org.beangle.commons.io.DefaultBinarySerializer
import java.io.ObjectInputStream

class HttpSessionRepo(cacheManager: CacheManager) extends CacheSessionRepo(cacheManager) {

  var geturl: String = _
  var accessUrl: String = _

  protected def getInternal(sessionId: String): Option[Session] = {
    HttpUtils.getResponseData(geturl.replace("{id}", sessionId)) match {
      case Some(is) =>
        val ois = new ObjectInputStream(is)
        val rs = Some(ois.readObject().asInstanceOf[Session])
        ois.close()
        rs
      case None => None
    }
  }

  def heartbeat(session: Session): Boolean = {
    var surl = accessUrl.replace("{id}", session.id)
    surl = surl.replace("{time}", session.lastAccessAt.getEpochSecond.toString)
    val url = new URL(surl)
    val hc = url.openConnection().asInstanceOf[HttpURLConnection]
    hc.setRequestMethod("get")
    hc.getResponseCode == 200
  }
}