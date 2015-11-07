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

import org.beangle.security.authc.{ AbstractAccountRealm, Account, AccountStore, AuthenticationToken, BadCredentialsException }
import org.beangle.security.web.authc.PreauthToken
import CasConfig.TicketName
import org.beangle.security.authc.AbstractAccountStoreRealm

class CasToken(t: String) extends PreauthToken(t) {

  def ticket: String = principal.toString

  details += CasConfig.TicketName -> principal.toString
}

class DefaultCasRealm(accountStore: AccountStore, val ticketValidator: TicketValidator)
    extends AbstractAccountStoreRealm(accountStore) {

  protected override def determinePrincipal(token: AuthenticationToken): Any = {
    try {
      val ticket = token.details(TicketName).toString
      val assertion = ticketValidator.validate(ticket, token.details("url").toString)
      assertion.principal
    } catch {
      case e: TicketValidationException => throw new BadCredentialsException("Bad credentials :" + token.details(TicketName), token, e)
    }
  }

  protected override def credentialsCheck(token: AuthenticationToken, account: Account): Unit = {}

  override def supports(token: AuthenticationToken): Boolean = token.isInstanceOf[CasToken]
}
