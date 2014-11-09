package org.beangle.security.web.authc

import org.beangle.commons.web.util.RequestUtils
import org.beangle.security.authc.DetailNames.{Agent, Host, Os, Server}

import javax.servlet.http.HttpServletRequest

object WebDetails {
  def get(request: HttpServletRequest): Map[String, String] = {
    val agent = RequestUtils.getUserAgent(request)
    val server = request.getLocalAddr() + ":" + request.getLocalPort()
    val host = RequestUtils.getIpAddr(request)
    import org.beangle.security.authc.DetailNames._
    Map((Os, agent.os.toString), (Agent, agent.browser.toString), (Host, host), (Server, server))
  }
}