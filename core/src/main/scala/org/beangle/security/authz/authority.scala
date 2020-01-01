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

object AuthorityDomain {
  def apply(roots: collection.Iterable[String], authorities: collection.Seq[Authority]): AuthorityDomain = {
    new AuthorityDomain(roots.toSet, authorities.map(x => (x.resourceName, x)).toMap)
  }

  def empty: AuthorityDomain = {
    new AuthorityDomain(Set.empty, Map.empty)
  }
}

class AuthorityDomain(val roots: Set[String], val authorities: Map[String, Authority]) {

  def isEmpty: Boolean = {
    authorities.isEmpty && roots.isEmpty
  }
}

object Authority {
  def apply(resourceName: String, scope: String, roles: Set[String]): Authority = {
    new Authority(resourceName, Scopes.withName(scope).asInstanceOf[Scopes.Scope], roles)
  }
}

case class Authority(resourceName: String, scope: Scopes.Scope, roles: Set[String]) {

  def matches(authorities: Array[String]): Boolean = {
    authorities.exists(roles.contains)
  }
}
