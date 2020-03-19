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
package org.beangle.security.web.authc

import java.time.Instant

import javax.servlet.http.HttpServletRequest
import org.beangle.commons.codec.digest.Digests
import org.beangle.commons.lang.Strings
import org.beangle.commons.logging.Logging
import org.beangle.commons.web.util.RequestUtils

/**
  * Source of the username supplied with pre-authenticated authentication
  * request. The username can be supplied in the request: in cookie, request
  * header, request parameter or as ServletRequest.getRemoteUser().
  */
trait UsernameSource {
  /**
    * Obtain username supplied in the request.
    */
  def resolveUser(request: HttpServletRequest, credential: Any): Option[String]

  def getCredential(request: HttpServletRequest): Option[Any]
}

/**
  * Abtain username by cookie
  */
abstract class AbstractCookieUsernameSource extends UsernameSource {

  var cookieName: String = _

  override def getCredential(request: HttpServletRequest): Option[Any] = {
    val cookies = request.getCookies
    if (cookies != null) {
      cookies.find(c => c.getName == cookieName) match {
        case Some(c) => Some(c.getValue)
        case None => None
      }
    }
    None
  }
}

/**
  * Source of the username supplied with pre-authenticated authentication request
  * as remote user header value. Optionally can strip prefix: "domain\\username"
  * -> "username", if <tt>stripPrefix</tt> property value is "true".
  */
class RemoteUsernameSource extends UsernameSource with Logging {

  var stripPrefix = true

  override def getCredential(request: HttpServletRequest): Option[Any] = {
    var username: String = null
    val p = request.getUserPrincipal
    if (null != p) username = p.getName
    if (Strings.isEmpty(username)) username = request.getRemoteUser
    if (null != username && stripPrefix) username = stripPrefix(username)
    if (null != username) logger.debug(s"Obtained username=[$username] from remote user")
    Option(username)
  }

  override def resolveUser(request: HttpServletRequest, credential: Any): Option[String] = {
    Some(credential.toString)
  }

  private def stripPrefix(userName: String): String = {
    val index = userName.lastIndexOf("\\")
    if (-1 == index) userName else userName.substring(index + 1)
  }
}

class ParameterUsernameSource extends UsernameSource with Logging {

  var enableExpired = true

  // default 10min second
  var expiredTime = 600

  var timeParam = "t"

  var userParam = "cid"

  var digestParam = "s"

  var extra = "123456!"

  override def getCredential(request: HttpServletRequest): Option[Any] = {
    Option(request.getParameter(digestParam))
  }

  override def resolveUser(request: HttpServletRequest, credential: Any): Option[String] = {
    val ip = RequestUtils.getIpAddr(request)
    val cid = request.getParameter(userParam)
    val timeParamStr = request.getParameter(timeParam)
    val t: Long = if (null == timeParamStr) 0L else java.lang.Long.valueOf(timeParamStr)

    val s = credential.toString
    if (0 == t || null == cid || null == ip) None
    else {
      val full = cid + "," + ip + "," + t + "," + extra
      val digest = Digests.md5Hex(full)
      if (logger.isDebugEnabled) {
        logger.debug(s"user $cid at :$ip")
        logger.debug(s"time:$t digest:$s ")
        logger.debug(s"full:$full")
        logger.debug(s"my_digest:$digest")
      }
      if (digest.equals(s)) {
        val now = Instant.now.getEpochSecond
        if (enableExpired && (Math.abs(now - t) > expiredTime)) {
          logger.debug(s"user $cid time expired:server time:$now and given time :$t")
          None
        } else {
          logger.debug(s"user $cid login at server time:$now")
          Some(cid)
        }
      } else None
    }
  }
}
