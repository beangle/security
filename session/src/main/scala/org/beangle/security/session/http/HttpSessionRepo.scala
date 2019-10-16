/*
 * Beangle, Agile Development Scaffold and Toolkits.
 *
 * Copyright © 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.session.http

import java.net.{HttpURLConnection, URL}

import org.beangle.cache.CacheManager
import org.beangle.commons.io.BinarySerializer
import org.beangle.commons.lang.Strings
import org.beangle.commons.lang.Strings.replace
import org.beangle.commons.net.http.{HttpMethods, HttpUtils, Https}
import org.beangle.security.session.cache.CacheSessionRepo
import org.beangle.security.session.{DefaultSession, Session}

class HttpSessionRepo(cacheManager: CacheManager, serializer: BinarySerializer)
  extends CacheSessionRepo(cacheManager) {

  var geturl: String = _
  var accessUrl: String = _
  var findUrl: String = _

  protected def getInternal(sessionId: String): Option[Session] = {
    HttpUtils.getData(replace(geturl, "{id}", sessionId)) map { data =>
      serializer.asObject(classOf[DefaultSession], data)
    }
  }


  override def findByPrincipal(principal: String): collection.Seq[Session] = {
    HttpUtils.getText(replace(findUrl, "{principal}", principal)) match {
      case None => List.empty
      case Some(data) => Strings.split(data).toSeq.flatMap(getInternal(_))
    }
  }

  def heartbeat(session: Session): Boolean = {
    var surl = replace(accessUrl, "{id}", session.id)
    surl = replace(surl, "{time}", session.lastAccessAt.getEpochSecond.toString)
    val url = new URL(surl)
    val hc = url.openConnection().asInstanceOf[HttpURLConnection]
    hc.setRequestMethod(HttpMethods.GET)
    Https.noverify(hc)
    hc.getResponseCode == 200
  }
}
