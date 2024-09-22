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
import org.beangle.security.authc.{CredentialStore, Principals}
import org.beangle.security.realm.ldap.LdapUserStore.{UserPassword, UserStatus}

class LdapCredentialStore(userStore: LdapUserStore) extends CredentialStore {

  override def getPassword(principal: Any): Option[String] = {
    val username = Principals.getName(principal)
    userStore.getUserDN(username) match {
      case Some(dn) =>
        userStore.getAttribute(dn, UserPassword).map(p => new String(p.asInstanceOf[Array[Byte]]))
      case None =>
        None
    }
  }

  def getActivePassword(principal: Any): Option[(String, Boolean)] = {
    val username = Principals.getName(principal)
    userStore.getUserDN(username) match {
      case Some(dn) =>
        val attrs = userStore.getAttributes(dn, UserPassword, UserStatus)
        val active = attrs.get(UserStatus).forall(s => LdapUserStore.isActive(s.toString))
        attrs.get(UserPassword).map(p => (new String(p.asInstanceOf[Array[Byte]]), active))
      case None =>
        None
    }
  }

  override def updatePassword(principal: Any, rawPassword: String): Unit = {
    val username = Principals.getName(principal)
    userStore.getUserDN(username) foreach { dn =>
      userStore.updateAttribute(dn, LdapUserStore.UserPassword, rawPassword.getBytes)
    }
  }

}
