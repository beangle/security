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
import jakarta.servlet.{FilterChain, ServletRequest, ServletResponse}
import org.beangle.commons.bean.Initializing
import org.beangle.commons.logging.Logging
import org.beangle.security.SecurityException
import org.beangle.security.authc.AuthenticationException
import org.beangle.security.authz.AccessDeniedException
import org.beangle.security.context.SecurityContext
import org.beangle.security.web.EntryPoint
import org.beangle.web.servlet.intercept.Interceptor

class SecurityInterceptor extends Interceptor, Logging, Initializing {
  var securityContextBuilder: SecurityContextBuilder = _
  var entryPoint: EntryPoint = _
  var accessDeniedHandler: AccessDeniedHandler = _
  var filters: List[SecurityFilter] = _
  var hasFilter = false

  override def init(): Unit = {
    hasFilter = null != filters && filters.nonEmpty
  }

  override def preInvoke(req: HttpServletRequest, res: HttpServletResponse): Boolean = {
    try {
      val ctx = securityContextBuilder.find(req, res)
      SecurityContext.set(ctx)
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
        else sendStartAuthentication(request, response, new AuthenticationException("access denied", ade))
      case se: SecurityException =>
        sendStartAuthentication(request, response, new AuthenticationException(se.getMessage, se))
    }
  }

  private def sendStartAuthentication(request: ServletRequest, response: ServletResponse, reason: AuthenticationException): Unit = {
    SecurityContext.clear()
    entryPoint.commence(request.asInstanceOf[HttpServletRequest], response.asInstanceOf[HttpServletResponse], reason)
  }

  def postInvoke(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  }
}

class ResultChain(val filterIter: Iterator[_ <: SecurityFilter]) extends FilterChain {
  override def doFilter(request: ServletRequest, response: ServletResponse): Unit = {
    if (filterIter.hasNext) filterIter.next().doFilter(request, response, this)
  }
}
