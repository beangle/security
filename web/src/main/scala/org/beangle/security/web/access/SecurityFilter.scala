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
package org.beangle.security.web.access;

import java.io.IOException
import scala.annotation.elidable
import scala.annotation.elidable.FINE
import org.beangle.commons.web.filter.GenericHttpFilter
import org.beangle.security.SecurityException
import org.beangle.security.authc.{ AnonymousToken, AuthenticationException }
import org.beangle.security.authz.AccessDeniedException
import org.beangle.security.context.ContextHolder
import org.beangle.security.web.EntryPoint
import javax.servlet.{ FilterChain, ServletRequest, ServletResponse }
import org.beangle.commons.web.filter.FilterChainProxy
import org.beangle.commons.inject.ContainerHook
import org.beangle.commons.inject.Container

class SecurityFilter extends FilterChainProxy with ContainerHook {

  var accessDeniedHandler: AccessDeniedHandler = _
  var entryPoint: EntryPoint = _

  override def doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain): Unit = {
    try {
      new VirtualFilterChain(chain, getFilters(request)).doFilter(request, response)
    } catch {
      case ioe: IOException => throw ioe
      case bse: SecurityException => handleException(request, response, chain, bse)
      case ex: Exception => throw ex
    }
  }

  def notify(container: Container) {
    val handlers = container.getBeans(classOf[AccessDeniedHandler])
    if (handlers.size != 1) require(null != accessDeniedHandler, "AccessDeniedHandler required");
    else this.accessDeniedHandler = handlers.values.head

    val entryPoints = container.getBeans(classOf[EntryPoint])
    if (entryPoints.size != 1) require(null != entryPoint, "authenticationEntryPoint must be specified");
    else this.entryPoint = entryPoints.values.head
  }

  private def handleException(request: ServletRequest, response: ServletResponse, chain: FilterChain,
    exception: SecurityException): Unit = {
    exception match {
      case ae: AuthenticationException =>
        debug("Authentication exception occurred", ae);
        sendStartAuthentication(request, response, chain, ae)
      case ade: AccessDeniedException =>
        if (ContextHolder.hasValidContext) {
          accessDeniedHandler.handle(request, response, ade)
        } else {
          sendStartAuthentication(request, response, chain, new AuthenticationException("access denied", ade));
        }
    }
  }

  protected def sendStartAuthentication(request: ServletRequest, response: ServletResponse, chain: FilterChain,
    reason: AuthenticationException): Unit = {
    ContextHolder.context = null
    entryPoint.commence(request, response, reason);
  }

}
