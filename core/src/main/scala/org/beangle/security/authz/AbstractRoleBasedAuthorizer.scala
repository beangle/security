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
package org.beangle.security.authz

import org.beangle.commons.bean.Initializing
import org.beangle.security.authc.{Account, DefaultAccount}
import org.beangle.security.context.SecurityContext
import org.beangle.security.util.{SecurityDaemon, Task}

abstract class AbstractRoleBasedAuthorizer extends Authorizer with Initializing {

  var domain: RoleAuthorityDomain = RoleAuthorityDomain.empty

  var unknownIsProtected = true

  var refreshSeconds = 5 * 60

  override def isPermitted(context: SecurityContext): Boolean = {
    if (context.root) return true

    val resourceName = context.request.resource.toString
    val raOption = domain.authorities.get(resourceName)
    raOption match {
      case None => if (unknownIsProtected) context.isValid else false
      case Some(ra) =>
        ra.scope match {
          case Scopes.Public => true //public
          case Scopes.Protected => context.isValid //protected
          case _ => //private
            context.session match {
              case Some(session) =>
                ra.matches(session.principal.asInstanceOf[Account].authorities)
              case None => false
            }
        }
    }
  }

  override def init(): Unit = {
    SecurityDaemon.start("Beangle Authority", refreshSeconds, new DomainFetcher(this))
  }

  override def isRoot(user: String): Boolean = {
    domain.roots.contains(user)
  }

  def fetchDomain(): RoleAuthorityDomain
}

class DomainFetcher(authorizer: AbstractRoleBasedAuthorizer) extends Task {
  override def run(): Unit = {
    authorizer.domain = authorizer.fetchDomain()
  }
}
