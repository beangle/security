/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2014, Beangle Software.
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

import java.io.IOException

import org.beangle.commons.inject.{ Container, ContainerHook }
import org.beangle.commons.web.filter.MatchedCompositeFilter
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
import java.{ util => ju }
/**
 *  handle
 *  <ul>
 *  <li> Exception handling
 *  <li> Context Holder loading and clear
 *  <li> Session access info update and concurrent logic
 *  </ul>
 */
class SecurityFilter(filters: List[Filter], val registry: SessionRegistry, val entryPoint: EntryPoint, val accessDeniedHandler: AccessDeniedHandler)
  extends MatchedCompositeFilter(MatchedCompositeFilter.build(filters)) {

  var expiredUrl: String = _
  var logoutHandler: LogoutHandler = _

  override def doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain): Unit = {
    try {
      val request = req.asInstanceOf[HttpServletRequest]
      val hs = request.getSession(true)
      val sid = SessionId(hs.getId)
      var breakChain = false
      if (null != hs) registry.get(sid).foreach { s =>
        if (s.expired) {
          breakChain = true
          registry.remove(sid)
          hs.invalidate()
          if (null != logoutHandler) logoutHandler.logout(req, res, s)
          if (null != expiredUrl) RedirectUtils.sendRedirect(request, res.asInstanceOf[HttpServletResponse], expiredUrl)
          else {
            res.getWriter().print(
              "This session has been expired (possibly due to multiple concurrent logins being attempted as the same user).")
            res.flushBuffer()
          }
        } else {
          s.access(new ju.Date(), RequestUtils.getServletPath(request))
          SecurityContext.session = s
        }
      }
      if (!breakChain) new VirtualFilterChain(chain, getFilters(req)).doFilter(req, res)
    } catch {
      case ioe: IOException => throw ioe
      case bse: SecurityException => handleException(req, res, chain, bse)
      case ex: Exception => throw ex
    } finally {
      SecurityContext.session = null
    }
  }

  private def handleException(request: ServletRequest, response: ServletResponse, chain: FilterChain,
    exception: SecurityException): Unit = {
    exception match {
      case ae: AuthenticationException =>
        debug("Authentication exception occurred", ae);
        sendStartAuthentication(request, response, chain, ae)
      case ade: AccessDeniedException =>
        if (SecurityContext.hasValidContext) accessDeniedHandler.handle(request, response, ade)
        else sendStartAuthentication(request, response, chain, new AuthenticationException("access denied", ade));
    }
  }

  protected def sendStartAuthentication(request: ServletRequest, response: ServletResponse, chain: FilterChain,
    reason: AuthenticationException): Unit = {
    SecurityContext.session = null
    entryPoint.commence(request.asInstanceOf[HttpServletRequest], response.asInstanceOf[HttpServletResponse], reason);
  }

}
