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

package org.beangle.security.web.session

import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.web.servlet.util.CookieUtils

class CookieSessionIdReader(val idName: String) extends SessionIdReader {

  override def getId(request: HttpServletRequest, response: HttpServletResponse): Option[String] = {
    var psid = request.getParameter(idName)

    if (null == psid) {
      val header = request.getHeader("Authorization")
      if (header != null) {
        if (header.startsWith("Bearer ")) {
          psid = header.substring("Bearer ".length)
        } else {
          psid = header
        }
      }
    }

    if (null == psid) {
      Option(CookieUtils.getCookieValue(request, idName))
    } else {
      Some(psid)
    }
  }

}
