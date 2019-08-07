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

import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.security.authc.PreauthToken
import org.beangle.security.realm.cas.CasConfig.getLocalServer
import org.beangle.security.web.WebSecurityManager
import org.beangle.security.web.authc.AbstractPreauthFilter

/**
 * Processes a CAS service ticket.
 */
class CasPreauthFilter(securityManager: WebSecurityManager, config: CasConfig, ticketValidator: TicketValidator)
  extends AbstractPreauthFilter(securityManager) {

  var casEntryPoint: CasEntryPoint = _

  protected override def resovleToken(req: HttpServletRequest, res: HttpServletResponse, credentials: Any): Option[PreauthToken] = {
    val url = casEntryPoint.constructServiceUrl(req, res, null, getLocalServer(req))
    Some(new PreauthToken(ticketValidator.validate(credentials.toString, url), credentials))
  }

  protected[cas] override def getCredentials(request: HttpServletRequest): Option[Any] = {
    Option(request.getParameter(CasConfig.TicketName))
  }

}
