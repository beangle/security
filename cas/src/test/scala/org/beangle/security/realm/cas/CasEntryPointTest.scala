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
package org.beangle.security.realm.cas

import java.net.URLEncoder
import scala.annotation.elidable
import scala.annotation.elidable.FINE
import org.beangle.commons.logging.Logging
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.{ mock, verify, when }
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.scalatest.{ FunSpec, Matchers }
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }
import org.scalatest.junit.JUnitRunner
import org.beangle.security.web.session.ParamSessionIdPolicy

@RunWith(classOf[JUnitRunner])
class CasEntryPointTest extends FunSpec with Matchers with Logging {
  describe("CasConfig") {
    it("should worked on getter/setter") {
      val config = new CasConfig("https://cas")
      assert("https://cas" == config.casServer)
    }
  }

  describe("CasEntryPoint") {
    it("commence redirect") {
      val config = new CasConfig("https://cas")
      config.renew = false
      val ep = new CasEntryPoint(config)
      ep.sessionIdReader = new ParamSessionIdPolicy
      val request = mock(classOf[HttpServletRequest])
      when(request.getRequestURI()).thenReturn("/bigWebApp/some_path")
      when(request.getServerName()).thenReturn("mycompany.com")
      when(request.getScheme()).thenReturn("https")
      when(request.getServerPort()).thenReturn(443)
      val response = mockResponse()

      ep.commence(request, response, null)
      verify(response).sendRedirect(
        "https://cas/login?service="
          + URLEncoder.encode("https://mycompany.com/bigWebApp/some_path", "UTF-8") + "&sid_name=JSESSIONID")
    }

    it("commence with renew") {
      val config = new CasConfig("https://cas")
      config.renew = true
      val ep = new CasEntryPoint(config)
      ep.sessionIdReader = new ParamSessionIdPolicy
      val request = mock(classOf[HttpServletRequest])
      when(request.getRequestURI()).thenReturn("/bigWebApp/some_path")
      when(request.getServerName()).thenReturn("mycompany.com")
      when(request.getScheme()).thenReturn("https")
      when(request.getServerPort()).thenReturn(443)

      val response = mockResponse()

      ep.commence(request, response, null)
      verify(response).sendRedirect(
        "https://cas/login?service="
          + URLEncoder.encode("https://mycompany.com/bigWebApp/some_path", "UTF-8") + "&renew=true&sid_name=JSESSIONID")

    }
    it("constuct service url") {
      val config = new CasConfig("http://www.mycompany.com/cas")
      val request = mock(classOf[HttpServletRequest])
      when(request.getRequestURI()).thenReturn("/demo/home.action")
      when(request.getServletPath()).thenReturn("/home.action")
      when(request.getContextPath()).thenReturn("/demo")
      when(request.getScheme()).thenReturn("http")

      val entryPoint = new CasEntryPoint(config)
      val response = mock(classOf[HttpServletResponse])
      val urlEncodedService = entryPoint.constructServiceUrl(request, response, null,
        CasConfig.getLocalServer(request))
      logger.debug(urlEncodedService)

      val urlEncodedService2 = entryPoint.constructServiceUrl(request, response, null,
        "localhost:8080")
      logger.debug(urlEncodedService2)
    }
  }

  private def mockResponse(): HttpServletResponse = {
    val response = mock(classOf[HttpServletResponse])
    when(response.encodeURL(any(classOf[String]))).`then`(new Answer[String]() {
      def answer(invocation: InvocationOnMock): String = {
        invocation.getArguments()(0).toString()
      }
    })
    response
  }
}
