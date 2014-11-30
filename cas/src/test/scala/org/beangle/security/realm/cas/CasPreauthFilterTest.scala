package org.beangle.security.realm.cas

import org.beangle.commons.logging.Logging
import org.beangle.security.authc.{ AuthenticationInfo, AuthenticationToken, Authenticator, BadCredentialsException }
import org.beangle.security.mgt.DefaultSecurityManager
import org.junit.runner.RunWith
import org.mockito.Mockito.{ mock, when }
import org.scalatest.{ FunSpec, Matchers }
import javax.servlet.FilterChain
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse, HttpSession }
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class CasPreauthFilterTest extends FunSpec with Matchers with Logging {

  val authenticator = new Authenticator() {
    def authenticate(token: AuthenticationToken): AuthenticationInfo = {
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