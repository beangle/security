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

package org.beangle.security.authc

class DefaultAccountRealm(accountStore: AccountStore, credentialChecker: CredentialChecker)
  extends AbstractAccountRealm {

  def this(accountStore: AccountStore) = {
    this(accountStore, null)
  }

  protected override def loadAccount(principal: Any): Option[Account] = {
    accountStore.load(principal)
  }

  protected override def credentialCheck(token: AuthenticationToken): Boolean = {
    credentialChecker.check(token.principal, token.credential)
  }
}
