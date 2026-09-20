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

import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.security.SecurityLogger
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.{mock, verify, when}
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

import java.net.URLEncoder

class CasEntryPointTest extends AnyFunSpec, Matchers {
  describe("CasConfig") {
    it("should worked on getter/setter") {
      val config = new CasConfig("https://cas")
      assert("https://cas" == config.casServer)
    }
  }

  describe("CasEntryPoint") {
    it("commence redirect") {
      val config = new CasConfig("https://cas")
      val ep = new CasEntryPoint(config)
      ep.sessionIdReader = Some(new ParamSessionIdPolicy)
      val request = mock(classOf[HttpServletRequest])
      when(request.getRequestURI).thenReturn("/bigWebApp/some_path")
      when(request.getServerName).thenReturn("mycompany.com")
      when(request.getScheme).thenReturn("https")
      when(request.getServletPath).thenReturn("/some_path")
      when(request.getServerPort).thenReturn(443)
      val response = mockResponse()

      ep.commence(request, response, null)
      verify(response).sendRedirect(
        "https://cas/login?service="
          + URLEncoder.encode("https://mycompany.com/bigWebApp/some_path", "UTF-8") + "&sid_name=JSESSIONID")
    }

    it("commence with gateway") {
      val config = new CasConfig("https://school.edu.cn/cas")
      config.gateway = true
      config.localLoginUri = Some("/mylogin.jsp")
      val ep = new CasEntryPoint(config)
      ep.sessionIdReader = Some(new ParamSessionIdPolicy)
      val request = mock(classOf[HttpServletRequest])
      when(request.getContextPath).thenReturn("/bigWebApp")
      when(request.getRequestURI).thenReturn("/bigWebApp/some_path")
      when(request.getServerName).thenReturn("mycompany.com")
      when(request.getScheme).thenReturn("https")
      when(request.getServerPort).thenReturn(443)

      val response = mockResponse()
      ep.commence(request, response, null)
      val originUrl = "https://mycompany.com/bigWebApp/some_path"
      val loginUrl = "https://mycompany.com/bigWebApp/mylogin.jsp?service=" + URLEncoder.encode(originUrl, "UTF-8")
      verify(response).sendRedirect(
        "https://school.edu.cn/cas/login?service="
          + URLEncoder.encode(loginUrl, "UTF-8") + "&gateway=true&sid_name=JSESSIONID")

    }
    it("constuct service url") {
      val config = new CasConfig("http://www.mycompany.com/cas")
      val request = mock(classOf[HttpServletRequest])
      when(request.getServerName).thenReturn("localhost")
      when(request.getRequestURI).thenReturn("/demo/home.action")
      when(request.getServletPath).thenReturn("/home.action")
      when(request.getContextPath).thenReturn("/demo")
      when(request.getServerPort).thenReturn(8080)
      when(request.getScheme).thenReturn("http")
      when(request.getQueryString).thenReturn("a=1&b=2")

      val entryPoint = new CasEntryPoint(config)
      val urlEncodedService = entryPoint.serviceUrl(request)
      SecurityLogger.debug(urlEncodedService)
      val urlEncodedService2 = entryPoint.serviceUrl(request)
      SecurityLogger.debug(urlEncodedService2)
    }

    it("keep service stable between cas login and ticket validate") {
      val config = new CasConfig("https://cas.shcmusic.edu.cn/cas")
      config.localLoginUri = Some("/cas/login")
      val entryPoint = new CasEntryPoint(config)

      // 直接访问本站登录页,/cas/login?openid=x&username=y&service=z
      checkRoundTrip(
        entryPoint,
        "/cas/login",
        "openid=ofmK86UD1tak5il52old_6Anj_FQ&username=10823&renew=true" +
          "&service=https%3a%2f%2fyjs.shcmusic.edu.cn%2fedu%2fteaching%2fmini-coach")
      // 访问业务页面,entry point会跳转到 /cas/login?service=业务页
      checkRoundTrip(entryPoint, "/edu/teaching/mini-coach", "openid=ofmK86UD1tak5il52old_6Anj_FQ&username=10823")

      // cas协议参数不参与service比对
      val service = entryPoint.serviceUrl(mockRequest("/cas/login", "renew=true&ticket=ST-95841"))
      assert(service == "https://yjs.shcmusic.edu.cn/cas/login")
    }

    def checkRoundTrip(entryPoint: CasEntryPoint, uri: String, queryString: String): Unit = {
      // 注册到cas的service,即cas登录成功后回跳的地址
      val registeredService = entryPoint.localLoginUrl(mockRequest(uri, queryString))

      // 回跳时url上带ticket,过滤器用serviceUrl(req)构造出校验用的service
      val pathStart = registeredService.indexOf('/', registeredService.indexOf("://") + 3)
      val queryStart = registeredService.indexOf('?', pathStart)
      val backRequest =
        if (queryStart < 0) mockRequest(registeredService.substring(pathStart), "ticket=ST-95841")
        else mockRequest(registeredService.substring(pathStart, queryStart),
          registeredService.substring(queryStart + 1) + "&ticket=ST-95841")
      val suppliedService = entryPoint.serviceUrl(backRequest)

      SecurityLogger.debug("registered:" + registeredService)
      SecurityLogger.debug("supplied:" + suppliedService)
      assert(registeredService == suppliedService)
    }

    def mockRequest(uri: String, queryString: String): HttpServletRequest = {
      val request = mock(classOf[HttpServletRequest])
      when(request.getServerName).thenReturn("yjs.shcmusic.edu.cn")
      when(request.getRequestURI).thenReturn(uri)
      when(request.getContextPath).thenReturn("")
      when(request.getServerPort).thenReturn(443)
      when(request.getScheme).thenReturn("https")
      when(request.getQueryString).thenReturn(queryString)
      request
    }
  }

  private def mockResponse(): HttpServletResponse = {
    val response = mock(classOf[HttpServletResponse])
    when(response.encodeURL(any(classOf[String]))).`then`(new Answer[String]() {
      def answer(invocation: InvocationOnMock): String = {
        invocation.getArguments()(0).toString
      }
    })
    response
  }
}
