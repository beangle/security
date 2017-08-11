package org.beangle.security.session.http

import java.io.ObjectInputStream
import java.net.{ HttpURLConnection, URL }

import org.beangle.cache.CacheManager
import org.beangle.commons.net.http.HttpUtils
import org.beangle.security.session.Session
import org.beangle.security.session.cache.CacheSessionRepo

class HttpSessionRepo(cacheManager: CacheManager) extends CacheSessionRepo(cacheManager) {

  var geturl: String = _
  var accessUrl: String = _

  protected def getInternal(sessionId: String): Option[Session] = {
    HttpUtils.getData(geturl.replace("{id}", sessionId)) match {
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