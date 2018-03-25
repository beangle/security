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
package org.beangle.security.web.access

import java.time.Instant

import org.beangle.commons.bean.Initializing
import org.beangle.commons.logging.Logging
import org.beangle.commons.web.intercept.Interceptor
import org.beangle.commons.web.security.RequestConvertor
import org.beangle.security.SecurityException
import org.beangle.security.authc.AuthenticationException
import org.beangle.security.authz.{ AccessDeniedException, Authorizer }
import org.beangle.security.context.SecurityContext
import org.beangle.security.session.{ Session, SessionRepo }
import org.beangle.security.web.EntryPoint
import org.beangle.security.web.session.SessionIdReader

import javax.servlet.{ FilterChain, ServletRequest, ServletResponse }
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }

class SecurityInterceptor extends Interceptor with Logging with Initializing {
  var securityContextBuilder: SecurityContextBuilder = _
  var entryPoint: EntryPoint = _
  var accessDeniedHandler: AccessDeniedHandler = _
  var filters: List[SecurityFilter] = _
  var hasFilter = false

  override def init() {
    hasFilter = (null!=filters && !filters.isEmpty)
  }

  override def preInvoke(req: HttpServletRequest, res: HttpServletResponse): Boolean = {
    try {
      SecurityContext.set(securityContextBuilder.find(req))
      if (hasFilter) new ResultChain(filters.iterator).doFilter(req, res)
      true
    } catch {
      case bse: SecurityException =>
        handleException(req, res, bse); false
      case ex: Throwable => throw ex
    }
  }

  private def handleException(request: ServletRequest, response: ServletResponse, exception: SecurityException): Unit = {
    exception match {
      case ae: AuthenticationException =>
        sendStartAuthentication(request, response, ae)
      case ade: AccessDeniedException =>
        if (SecurityContext.get.isValid) accessDeniedHandler.handle(request, response, ade)
        else sendStartAuthentication(request, response, new AuthenticationException("access denied", ade));
    }
  }

  private def sendStartAuthentication(request: ServletRequest, response: ServletResponse, reason: AuthenticationException): Unit = {
    SecurityContext.clear()
    entryPoint.commence(request.asInstanceOf[HttpServletRequest], response.asInstanceOf[HttpServletResponse], reason);
  }

  def postInvoke(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  }
}

class ResultChain(val filterIter: Iterator[_ <: SecurityFilter]) extends FilterChain {
  override def doFilter(request: ServletRequest, response: ServletResponse): Unit = {
    if (filterIter.hasNext) filterIter.next.doFilter(request, response, this)
  }
}
