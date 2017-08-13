/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
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

import org.beangle.commons.web.filter.GenericHttpFilter
import org.beangle.commons.web.security.RequestConvertor
import org.beangle.security.authz.{ AccessDeniedException, Authorizer }
import org.beangle.security.context.SecurityContext

import javax.servlet.{ FilterChain, ServletRequest, ServletResponse }
import javax.servlet.http.HttpServletRequest

class AuthorizationFilter(val authorizer: Authorizer, val requestConvertor: RequestConvertor)
    extends GenericHttpFilter with SecurityFilter {

  override def doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
    if (!authorizer.isPermitted(SecurityContext.getSession, requestConvertor.convert(request.asInstanceOf[HttpServletRequest])))
      throw new AccessDeniedException(request, "access denied", null)
    chain.doFilter(request, response)
  }
}