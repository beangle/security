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

package org.beangle.security.realm.ldap

import org.beangle.commons.lang.Strings
import org.beangle.security.authc.{Account, AccountStore}

/**
 * Ldap User Store (RFC 4510)
 *
 * @see http://tools.ietf.org/html/rfc4510
 * @see http://www.rfc-base.org/rfc-4510.html
 * @see http://directory.apache.org/api/java-api.html
 */
trait LdapUserStore extends AccountStore {

  def getUserDN(uid: String): Option[String]

  def getAttribute(userDN: String, attrName: String): Option[Any]

  def getAttributes(userDN: String, attributeNames: String*): collection.Map[String, Any]

  def updateAttribute(dn: String, attribute: String, value: AnyRef): Unit

  def create(user: Account, password: String): Unit
}

object LdapUserStore {
  val CommonName = "cn"
  val UserPassword = "userPassword"
  val UserStatus = "inetUserStatus"

  private val inactiveStatuses = Set("inactive", "deleted")

  def isActive(status: String): Boolean = {
    Strings.isEmpty(status) || !inactiveStatuses.contains(status.toLowerCase())
  }
}
