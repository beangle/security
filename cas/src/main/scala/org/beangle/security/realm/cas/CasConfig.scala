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

import javax.servlet.http.HttpServletRequest
import org.beangle.commons.bean.Initializing
import org.beangle.commons.lang.{Assert, Strings}
import org.beangle.commons.web.util.RequestUtils

/** Cas 配置
 *
 * @see https://apereo.github.io/cas/4.2.x/protocol/CAS-Protocol-Specification.html
 */
object CasConfig {

  def getLocalServer(request: HttpServletRequest): String = {
    val sb = new StringBuilder()
    val scheme = if (RequestUtils.isHttps(request)) "https" else "http"
    val port = RequestUtils.getServerPort(request)
    val serverName = request.getServerName
    var includePort = true
    sb.append(scheme).append("://")
    includePort = port != (if (scheme == "http") 80 else 443)
    if (null != serverName) {
      sb.append(serverName)
      if (includePort && port > 0) sb.append(':').append(port)
    }
    sb.toString
  }

  val TicketName = "ticket"

  val ServiceName  = "service"
}

class CasConfig(server: String) extends Initializing {
  val casServer: String = Strings.stripEnd(server, "/")

  /** 目标cas是否是网关 */
  var gateway = false

  var loginUri = "/login"

  var logoutUri = "/logout"

  var validateUri = "/serviceValidate"

  var checkAliveUri = "/checkAlive"

  var localLoginUri: Option[String] = None

  def init(): Unit = {
    Assert.notEmpty(this.loginUri, "loginUri must be specified. like /login")
    if (gateway) {
      require(localLoginUri.nonEmpty, "local login uri required when gateway is true")
    }
  }

  /**
   * The enterprise-wide CAS login URL. Usually something like
   * <code>https://www.mycompany.com/cas/login</code>.
   */
  def loginUrl: String = casServer + loginUri

  def logoutUrl: String = casServer + logoutUri
}
