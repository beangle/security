/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.session.http

import org.beangle.cache.CacheManager
import org.beangle.commons.io.BinarySerializer
import org.beangle.commons.lang.Strings
import org.beangle.commons.lang.Strings.replace
import org.beangle.commons.net.Networks
import org.beangle.commons.net.http.HttpUtils.{getData, getText}
import org.beangle.commons.net.http.{HttpMethods, Https}
import org.beangle.security.session.cache.CacheSessionRepo
import org.beangle.security.session.{DefaultSession, Session}

import java.net.{HttpURLConnection, URL}

class HttpSessionRepo(cacheManager: CacheManager, serializer: BinarySerializer)
  extends CacheSessionRepo(cacheManager) {

  var geturl: String = _
  var accessUrl: String = _
  var findUrl: String = _
  var expireUrl: String = _

  protected def getInternal(sid: String): Option[Session] = {
    val response = getData(replace(geturl, "{id}", sid))
    if (response.status == 200) {
      Some(serializer.asObject(classOf[DefaultSession], response.content.asInstanceOf[Array[Byte]]))
    } else {
      None
    }
  }

  override def findByPrincipal(principal: String): collection.Seq[Session] = {
    val response = getText(replace(findUrl, "{principal}", principal))
    if (response.status == 200) {
      Strings.split(response.getText).toSeq.flatMap(getInternal)
    } else {
      List.empty
    }
  }

  override def flush(session: Session): Boolean = {
    var surl = replace(accessUrl, "{id}", session.id)
    surl = replace(surl, "{time}", session.lastAccessAt.getEpochSecond.toString)
    val hc = Networks.openURL(surl).asInstanceOf[HttpURLConnection]
    hc.setRequestMethod(HttpMethods.GET)
    Https.noverify(hc)
    hc.getResponseCode == 200
  }

  override def expire(sid: String): Unit = {
    evict(sid)
    getText(replace(expireUrl, "{id}", sid))
  }
}
