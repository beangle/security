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
import org.beangle.security.context.SecurityContext
/**
 * Processes a CAS service ticket.
 */
class CasPreauthFilter(securityManager: SecurityManager, config: CasConfig, ticketValidator: TicketValidator)
    extends AbstractPreauthFilter(securityManager) {

  protected override def resovleToken(req: HttpServletRequest, res: HttpServletResponse, ticket: String): Option[PreauthToken] = {
    val url = CasEntryPoint.constructServiceUrl(req, res, null, getLocalServer(req), TicketName)
    try {
      Some(new PreauthToken(ticketValidator.validate(ticket, url).name, ticket))
    } catch {
      case e: TicketValidationException =>
        logger.error("Bad credentials :" + ticket, e)
        None
    }
  }

  protected[cas] override def getTokenStr(request: HttpServletRequest): Option[String] = {
    val ticket = request.getParameter(CasConfig.TicketName)
    if (ticket == null) {
      None
    } else {
      //FIXME need test
      val referer = request.getHeader("Referer")
      if (null == referer || !referer.startsWith(config.casServer)) None else Some(ticket)
    }
  }

}