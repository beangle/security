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

import org.beangle.security.web.authc.PreauthToken
import org.beangle.security.web.authc.AbstractPreauthFilter
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import org.beangle.security.mgt.SecurityManager
import CasConfig._
/**
 * Processes a CAS service ticket.
 */
class CasPreauthFilter(securityManager: SecurityManager, val config: CasConfig)
    extends AbstractPreauthFilter(securityManager) {

  protected[cas] override def getPreauthToken(request: HttpServletRequest, response: HttpServletResponse): PreauthToken = {
    val ticket = request.getParameter(CasConfig.TicketName)
    if (ticket == null) {
      null
    } else {
      val url = CasEntryPoint.constructServiceUrl(request, response, null, getLocalServer(request), TicketName, config.encode)
      val token = new CasToken(ticket)
      token.details += "url" -> url
      token
    }
  }
}