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
package org.beangle.security.web.authc

import org.beangle.commons.web.util.RequestUtils
import org.beangle.security.authc.AuthenticationToken.Details.{ Agent, Ip, Os }

import javax.servlet.http.HttpServletRequest

object WebDetails {
  def get(request: HttpServletRequest): Map[String, String] = {
    val agent = RequestUtils.getUserAgent(request)
    val server = request.getLocalAddr() + ":" + request.getLocalPort()
    val ip = RequestUtils.getIpAddr(request)
    Map((Os, agent.os.toString), (Agent, agent.browser.toString), (Ip, ip))
  }
}