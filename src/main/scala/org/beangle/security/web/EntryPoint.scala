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

package org.beangle.security.web

import jakarta.servlet.ServletException
import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.commons.lang.Strings
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.AuthenticationException
import org.beangle.web.servlet.url.UrlBuilder
import org.beangle.web.servlet.util.RedirectUtils

import java.io.IOException

trait EntryPoint {

  def isLocalLogin(req: HttpServletRequest, ae: AuthenticationException): Boolean

  def remoteLogin(request: HttpServletRequest, response: HttpServletResponse): Unit

  @throws(classOf[IOException])
  @throws(classOf[ServletException])
  def commence(request: HttpServletRequest, response: HttpServletResponse, ae: AuthenticationException): Unit
}

class UrlEntryPoint(val url: String) extends EntryPoint, Logging {

  var serverSideRedirect: Boolean = _

  /** Performs the redirect (or forward) to the login form URL. */
  override def commence(req: HttpServletRequest, res: HttpServletResponse, ae: AuthenticationException): Unit = {
    val failOnLogin = req.getRequestURI == Strings.replace(req.getContextPath + url, "//", "/")
    if (failOnLogin) {
      res.getWriter.println(ae.getMessage)
    } else {
      if (serverSideRedirect) {
        req.getRequestDispatcher(determineUrl(req, ae)).forward(req, res)
      } else {
        // redirect to login page. Use https if forceHttps true
        RedirectUtils.sendRedirect(req, res, determineUrl(req, ae))
      }
    }
  }

  /**
   * Allows subclasses to modify the login form URL that should be applicable
   * for a given request.
   */
  protected def determineUrl(req: HttpServletRequest, ae: AuthenticationException): String = {
    if (url.contains("${goto}")) Strings.replace(url, "${goto}", UrlBuilder.url(req))
    else url
  }

  override def isLocalLogin(req: HttpServletRequest, ae: AuthenticationException): Boolean = {
    true
  }

  override def remoteLogin(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    throw new org.beangle.security.SecurityException("UrlEntryPoint doesn't support remoteLogin", null)
  }
}
