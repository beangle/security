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

import org.beangle.commons.bean.Initializing
import org.beangle.commons.web.context.ServletContextHolder
import org.beangle.commons.web.util.{ CookieUtils }

import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }

/**
 * @author chaostone
 */
abstract class CookieSessionIdPolicy(name: String) extends CookieGenerator(name) with SessionIdPolicy with Initializing {

  override def getId(request: HttpServletRequest): Option[String] = {
    Option(CookieUtils.getCookieValue(request, name))
  }

  override def newId(request: HttpServletRequest, response: HttpServletResponse): String = {
    val newid = generateId(request)
    addCookie(request, response, newid)
    newid
  }

  def init(): Unit = {
    if (null == path) {
      val contextPath = ServletContextHolder.context.getContextPath
      path = if (!contextPath.endsWith("/")) contextPath + "/" else contextPath
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
