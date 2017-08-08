package org.beangle.security.session.http

import org.beangle.security.session.cache.CacheSessionRepo
import org.beangle.cache.CacheManager
import org.beangle.security.session.Session
import java.net.URL
import java.net.HttpURLConnection
import java.io.BufferedReader
import java.io.InputStreamReader

class HttpSessionRepo(cacheManager: CacheManager) extends CacheSessionRepo(cacheManager) {

  var geturl: String = _
  var accessUrl: String = _

  protected def getInternal(sessionId: String): Option[Session] = {
    var surl = geturl.replace("{id}", sessionId)
    val url = new URL(surl)
    val hc = url.openConnection().asInstanceOf[HttpURLConnection]
    hc.setRequestMethod("get")
    if (hc.getResponseCode == 200) {
      var in: BufferedReader = null
      in = new BufferedReader(new InputStreamReader(hc.getInputStream, "utf-8"))
      var line: String = in.readLine()
      val stringBuffer = new StringBuffer(255)
      stringBuffer.synchronized {
        while (line != null) {
          stringBuffer.append(line)
          stringBuffer.append("\n")
          line = in.readLine()
        }
        stringBuffer.toString
      }
    } else {
      None
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