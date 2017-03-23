/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
 *
 * Beangle is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Beangle is distributed in the hope that it will be useful.
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Beangle.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.web.session

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ParamSessionIdPolicy(val sessionIdParam: String = "JSESSIONID") extends SessionIdPolicy {

  override def getId(req: HttpServletRequest): String = {
    var sid: String = null
    if (null != sessionIdParam) {
      sid = req.getParameter(sessionIdParam)
    } else {
      val hs = req.getSession(false)
      if (null != hs) sid = hs.getId
    }
    if (null != sid) sid else null
  }

  override def newId(req: HttpServletRequest, res: HttpServletResponse): String = {
    if (null == sessionIdParam) {
      req.getSession(true).getId
    } else {
      null
    }
  }

  override def delId(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  }

  override def idName: String = {
    sessionIdParam
  }
}