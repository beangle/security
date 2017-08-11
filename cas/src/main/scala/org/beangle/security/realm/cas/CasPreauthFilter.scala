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
package org.beangle.security.realm.cas

import org.beangle.security.authc.PreauthToken
import org.beangle.security.web.WebSecurityManager
import org.beangle.security.web.authc.AbstractPreauthFilter

import CasConfig.{ TicketName, getLocalServer }
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }

/**
 * Processes a CAS service ticket.
 */
class CasPreauthFilter(securityManager: WebSecurityManager, config: CasConfig, ticketValidator: TicketValidator)
    extends AbstractPreauthFilter(securityManager) {

  protected override def resovleToken(req: HttpServletRequest, res: HttpServletResponse, credentials: Any): Option[PreauthToken] = {
    val url = CasEntryPoint.constructServiceUrl(req, res, null, getLocalServer(req), TicketName)
    Some(new PreauthToken(ticketValidator.validate(credentials.toString(), url), credentials))
  }

  protected[cas] override def getCredentials(request: HttpServletRequest): Option[Any] = {
    Option(request.getParameter(CasConfig.TicketName))
  }

}
