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

package org.beangle.security.realm.cas

import org.beangle.commons.logging.Logging
import org.beangle.security.authc.{ Account, AuthenticationToken, Authenticator, BadCredentialException }
import org.beangle.security.web.session.ParamSessionIdPolicy
import org.beangle.security.web.WebSecurityManager
import org.mockito.Mockito.{ mock, when }
import org.scalatest.matchers.should.Matchers
import org.scalatest.funspec.AnyFunSpec

import jakarta.servlet.FilterChain
import jakarta.servlet.http.{ HttpServletRequest, HttpServletResponse, HttpSession }

class CasPreauthFilterTest extends AnyFunSpec with Matchers with Logging {

  val authenticator = new Authenticator() {
    def authenticate(token: AuthenticationToken): Account = {
      throw new BadCredentialException("Rejected", token, null)
    }
  }
  val sm = new WebSecurityManager()
  sm.authenticator = authenticator
  sm.sessionIdPolicy = new ParamSessionIdPolicy

  val filter = new CasPreauthFilter(sm, new CasConfig("http://localhost/cas"), null)

  describe("CasPreauthFilter") {
    it("Normal operation") {
      assert(null != filter.getCredential(mockRequest()))
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
