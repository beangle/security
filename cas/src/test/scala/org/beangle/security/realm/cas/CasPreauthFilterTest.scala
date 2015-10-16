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
package org.beangle.security.realm.cas

import org.beangle.commons.logging.Logging
import org.beangle.security.authc.{ Account, AuthenticationToken, Authenticator, BadCredentialsException }
import org.beangle.security.mgt.DefaultSecurityManager
import org.junit.runner.RunWith
import org.mockito.Mockito.{ mock, when }
import org.scalatest.{ FunSpec, Matchers }
import org.scalatest.junit.JUnitRunner

import javax.servlet.FilterChain
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse, HttpSession }

@RunWith(classOf[JUnitRunner])
class CasPreauthFilterTest extends FunSpec with Matchers with Logging {

  val authenticator = new Authenticator() {
    def authenticate(token: AuthenticationToken): Account = {
      throw new BadCredentialsException("Rejected", token, null)
    }
  }
  val securityManager = new DefaultSecurityManager(authenticator, null, null)

  val filter = new CasPreauthFilter(securityManager, new CasConfig("http://localhost/cas"))

  describe("CasPreauthFilter") {
    it("Normal operation") {
      assert(null != filter.getPreauthToken(mockRequest(), mock(classOf[HttpServletResponse])))
    }

    it("Null Service Ticket Handled Gracefully") {
      try {
        filter.doFilter(mockRequest(), mock(classOf[HttpServletResponse]), mock(classOf[FilterChain]))
      } catch {
        case e: Throwable => assert(e.getClass == classOf[BadCredentialsException])
      }
    }
  }

  private def mockRequest(): HttpServletRequest = {
    val request = mock(classOf[HttpServletRequest])
    when(request.getParameter("ticket")) thenReturn ("ST-0-ER94xMJmn6pha35CQRoZ")
    when(request.getMethod) thenReturn ("GET")
    val session = mock(classOf[HttpSession])
    when(session.getId) thenReturn ("1")
    when(request.getSession(true)) thenReturn (session)
    request
  }
}