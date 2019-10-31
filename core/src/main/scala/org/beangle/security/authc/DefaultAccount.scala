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
package org.beangle.security.authc

import java.io.{ObjectInput, ObjectOutput}

import org.beangle.commons.collection.Collections
import org.beangle.commons.lang.Objects

object DefaultAccount {

  object StatusMask {
    val Locked = 1
    val Disabled = 2
    val AccountExpired = 4
    val CredentialExpired = 8
  }

}

import org.beangle.security.authc.DefaultAccount.StatusMask._

final class DefaultAccount extends Account {

  var name: String = _

  var description: String = _

  var remoteToken: Option[String] = None

  var status: Int = _

  var authorities: String = _

  var permissions: String = _

  var details: Map[String, String] = Map.empty

  var categoryId: Int = _

  def this(name: String, description: String) {
    this()
    this.name = name
    this.description = description
  }

  def this(account: Account) {
    this(account.name, account.description)
    account match {
      case da: DefaultAccount =>
        this.status = da.status
        this.categoryId = da.categoryId
      case _ =>
        this.accountExpired = account.accountExpired
        this.accountLocked = account.accountLocked
        this.disabled = account.disabled
        this.credentialExpired = account.credentialExpired
    }
    if (account.authorities != null) this.authorities = account.authorities.toString
    if (account.permissions != null) this.permissions = account.permissions.toString
    this.addDetails(account.details)
  }

  private def change(value: Boolean, mask: Int): Unit = {
    if (value) status = status | mask
    else {
      if ((status & mask) > 0) status = status ^ mask
    }
  }

  private def get(mask: Int): Boolean = (status & mask) > 0

  def accountExpired: Boolean = get(AccountExpired)

  def accountExpired_=(value: Boolean): Unit = change(value, AccountExpired)

  def accountLocked: Boolean = get(Locked)

  def accountLocked_=(locked: Boolean): Unit = change(locked, Locked)

  def credentialExpired: Boolean = get(CredentialExpired)

  def credentialExpired_=(expired: Boolean): Unit = change(expired, CredentialExpired)

  def disabled: Boolean = get(Disabled)

  def disabled_=(value: Boolean): Unit = change(value, Disabled)

  def addDetails(added: Map[String, Any]): this.type = {
    if (null != added) {
      added foreach {
        case (a, b) =>
          details += (a -> b.toString)
      }
    }
    this
  }

  def addRemoteToken(token: Any): this.type = {
    this.remoteToken = if (token == null) None else Some(token.toString)
    this
  }

  override def toString: String = {
    Objects.toStringBuilder(this).add("Name:", name)
      .add("AccountExpired: ", accountExpired)
      .add("credentialExpired: ", credentialExpired)
      .add("AccountLocked: ", accountLocked)
      .add("Disabled: ", disabled)
      .add("Authorities: ", authorities)
      .add("Permissions: ", permissions).toString
  }

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: DefaultAccount => Objects.equalsBuilder.add(this.name, test.name).isEquals
      case _ => false
    }
  }

  def writeExternal(out: ObjectOutput): Unit = {
    out.writeObject(name)
    out.writeObject(description)
    out.writeObject(remoteToken.orNull)
    out.writeInt(status)
    out.writeObject(authorities)
    out.writeObject(permissions)
    out.writeInt(details.size)
    details foreach {
      case (k, v) =>
        out.writeObject(k)
        out.writeObject(v)
    }
  }

  def readExternal(in: ObjectInput): Unit = {
    name = in.readObject.toString
    description = in.readObject.toString
    remoteToken = Option(in.readObject.asInstanceOf[String])
    status = in.readInt()
    authorities = in.readObject.asInstanceOf[String]
    permissions = in.readObject.asInstanceOf[String]
    val mapSize = in.readInt()
    val temp = Collections.newMap[String, String]
    (0 until mapSize) foreach { _ =>
      val k = in.readObject.toString
      val v = in.readObject.toString
      temp += (k -> v)
    }
    details = temp.toMap
  }
}
