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
package org.beangle.security.web.session

import javax.servlet.http.HttpServletResponse
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest

/**
 *
 * @author chaostone
 */
@deprecated("Using CookieGenderator within beangle-common-web_2.12:5.1.0.M3")
class CookieGenerator(val name: String) {
  var domain: String = _
  var path: String = _
  var secure: Boolean = _
  var httpOnly: Boolean = true
  var maxAge: Int = -1

  def addCookie(request: HttpServletRequest, response: HttpServletResponse, value: String): Unit = {
    val cookie = createCookie(request, value)
    cookie.setMaxAge(maxAge)
    cookie.setSecure(secure)
    cookie.setHttpOnly(httpOnly)
    response.addCookie(cookie)
  }

  def removeCookie(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val cookie = createCookie(request, "")
    cookie.setMaxAge(0)
    response.addCookie(cookie);
  }

  protected def createCookie(request: HttpServletRequest, value: String): Cookie = {
    val cookie = new Cookie(name, value);
    if (domain != null) {
      val serverName = request.getServerName
      if (serverName.contains(domain)) cookie.setDomain(domain)
    }

    cookie.setPath(path)
    cookie
  }
}
