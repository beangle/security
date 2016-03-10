/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2016, Beangle Software.
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
package org.beangle.security.web

import org.beangle.security.authc.AuthenticationException
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }
import org.beangle.commons.web.url.UrlBuilder
import org.beangle.commons.lang.Strings
import org.beangle.commons.web.util.RedirectUtils
import javax.servlet.RequestDispatcher
import org.beangle.commons.logging.Logging
import java.io.IOException
import javax.servlet.ServletException

trait EntryPoint {

  @throws(classOf[IOException])
  @throws(classOf[ServletException])
  def commence(request: HttpServletRequest, response: HttpServletResponse, ae: AuthenticationException): Unit
}

class UrlEntryPoint(val url: String) extends EntryPoint with Logging {

  var serverSideRedirect: Boolean = _

  /** Performs the redirect (or forward) to the login form URL. */
  override def commence(req: HttpServletRequest, res: HttpServletResponse, ae: AuthenticationException): Unit = {
    if (serverSideRedirect) {
      req.getRequestDispatcher(determineUrl(req, ae)).forward(req, res)
    } else {
      // redirect to login page. Use https if forceHttps true
      RedirectUtils.sendRedirect(req, res, determineUrl(req, ae))
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
}