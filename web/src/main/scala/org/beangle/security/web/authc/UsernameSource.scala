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

package org.beangle.security.web.authc

import java.time.Instant

import jakarta.servlet.http.HttpServletRequest
import org.beangle.commons.codec.digest.Digests
import org.beangle.commons.lang.Strings
import org.beangle.commons.logging.Logging
import org.beangle.web.servlet.util.RequestUtils

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
