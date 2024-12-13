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

package org.beangle.security.web.access

import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import jakarta.servlet.{ServletRequest, ServletResponse}
import org.beangle.commons.logging.Logging
import org.beangle.security.authz.AccessDeniedException
import org.beangle.web.servlet.context.ServletContextHolder

import java.io.File

/**
 * @author chaostone
 */
trait AccessDeniedHandler {

  /**
   * Handles an access denied failure.
   *
   */
  def handle(request: ServletRequest, response: ServletResponse, exception: AccessDeniedException): Unit
}

class DefaultAccessDeniedHandler(var errorPage: String) extends AccessDeniedHandler, Logging {

  def this() = {
    this(null)
  }

  if (null != errorPage) {
    require(errorPage.startsWith("/"), "errorPage must begin with '/'")
    val file = ServletContextHolder.context.getResource(errorPage)
    if (null == file) errorPage = null
  }

  def handle(request: ServletRequest, response: ServletResponse, exception: AccessDeniedException): Unit = {
    if (errorPage != null) {
      // Put exception into request scope (perhaps of use to a view)
      request.asInstanceOf[HttpServletRequest].setAttribute("403_EXCEPTION", exception)
      // Perform RequestDispatcher "forward"
      request.getRequestDispatcher(errorPage).forward(request, response)
    }

    if (!response.isCommitted) {
      // Send 403 (we do this after response has been written)
      response.asInstanceOf[HttpServletResponse].sendError(HttpServletResponse.SC_FORBIDDEN, exception.getMessage)
    }
  }

}
