/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
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
package org.beangle.security.web.access

import java.{ util => ju }
import org.beangle.commons.logging.Logging
import org.beangle.commons.web.filter.VirtualFilterChain
import org.beangle.commons.web.intercept.Interceptor
import org.beangle.commons.web.util.{ RedirectUtils, RequestUtils }
import org.beangle.security.SecurityException
import org.beangle.security.authc.AuthenticationException
import org.beangle.security.authz.AccessDeniedException
import org.beangle.security.context.SecurityContext
import org.beangle.security.session.{ SessionId, SessionRegistry }
import org.beangle.security.web.EntryPoint
import org.beangle.security.web.authc.LogoutHandler
import javax.servlet.{ Filter, FilterChain, ServletRequest, ServletResponse }
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }
import org.beangle.security.web.session.SessionIdPolicy

class SecurityInterceptor(val filters: List[Filter], val registry: SessionRegistry, val entryPoint: EntryPoint,
    val accessDeniedHandler: AccessDeniedHandler) extends Interceptor with Logging {

  private val hasEmptyFilter = !filters.isEmpty
  var expiredUrl: String = _
  var logoutHandler: LogoutHandler = _

  var sessionIdPolicy: SessionIdPolicy = _

  override def preInvoke(req: HttpServletRequest, res: HttpServletResponse): Boolean = {
    try {
      val sid = sessionIdPolicy.getSessionId(req)
      SecurityContext.session = null
      var breakChain = false
      registry.get(sid).foreach { s =>
        if (s.expired) {
          breakChain = true
          registry.remove(sid)
          val hs = req.getSession(false)
          if (null != hs) hs.invalidate()
          if (null != logoutHandler) logoutHandler.logout(req, res, s)
          if (null != expiredUrl) RedirectUtils.sendRedirect(req, res, expiredUrl)
          else {
            res.getWriter().print(
              "This session has been expired (possibly due to multiple concurrent logins being attempted as the same user).")
            res.flushBuffer()
          }
        } else {
          s.access(new ju.Date(), RequestUtils.getServletPath(req))
          SecurityContext.session = s
        }
      }
      if (breakChain) false
      else {
        if (!hasEmptyFilter) new ResultChain(filters.iterator).doFilter(req, res)
        true
      }
    } catch {
      case bse: SecurityException =>
        handleException(req, res, bse); false
      case ex: Throwable => throw ex
    }
  }

  private def handleException(request: ServletRequest, response: ServletResponse, exception: SecurityException): Unit = {
    exception match {
      case ae: AuthenticationException =>
        logger.debug("Authentication exception occurred", ae)
        sendStartAuthentication(request, response, ae)
      case ade: AccessDeniedException =>
        if (SecurityContext.hasValidContext) accessDeniedHandler.handle(request, response, ade)
        else sendStartAuthentication(request, response, new AuthenticationException("access denied", ade));
    }
  }

  private def sendStartAuthentication(request: ServletRequest, response: ServletResponse, reason: AuthenticationException): Unit = {
    SecurityContext.session = null
    entryPoint.commence(request.asInstanceOf[HttpServletRequest], response.asInstanceOf[HttpServletResponse], reason);
  }

  def postInvoke(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  }
}

class ResultChain(val filterIter: Iterator[_ <: Filter]) extends FilterChain {
  override def doFilter(request: ServletRequest, response: ServletResponse): Unit = {
    if (filterIter.hasNext) filterIter.next.doFilter(request, response, this)
  }
}