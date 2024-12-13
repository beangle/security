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
import org.beangle.commons.bean.Initializing
import org.beangle.web.servlet.context.ServletContextHolder
import org.beangle.web.servlet.util.{CookieGenerator, CookieUtils}

/**
 * @author chaostone
 */
abstract class CookieSessionIdPolicy(name: String) extends CookieGenerator(name), SessionIdPolicy, Initializing {

  override def getId(request: HttpServletRequest, res: HttpServletResponse): Option[String] = {
    val c = CookieUtils.getCookie(request, name)
    if null == c then None else Some(c.getValue)
  }

  override def newId(request: HttpServletRequest, response: HttpServletResponse): String = {
    val newid = generateId(request)
    addCookie(request, response, newid)
    newid
  }

  def init(): Unit = {
    if (null == this.path) {
      val c = ServletContextHolder.context
      if c == null then this.path = "/"
      else this.path = if (c.getContextPath.isEmpty) "/" else c.getContextPath
    }
  }

  override def delId(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    removeCookie(request, response)
  }

  override def idName: String = {
    name
  }

  protected def generateId(request: HttpServletRequest): String
}
