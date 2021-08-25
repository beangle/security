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

import org.beangle.commons.lang.Objects

import java.security.Principal

/**
 * Authentication Token used before authentication
 */
trait AuthenticationToken extends Principal with Serializable {

  def principal: Any

  def credential: Any

  var details: Map[String, Any] = Map.empty

  def addDetail(name: String, value: Any): Unit = {
    details += (name -> value)
  }

  def removeDetail(name: String): Option[Any] = {
    val rs = details.get(name)
    details -= name
    rs
  }

  override def getName: String = {
    Principals.getName(principal)
  }

  override def hashCode: Int = {
    if (null == principal) 629 else principal.hashCode()
  }

  def trusted: Boolean = {
    false
  }

}

/**
 * Simple Authentication Token
 */
@SerialVersionUID(3966615358056184985L)
class UsernamePasswordToken(val principal: Any, val credential: Any) extends AuthenticationToken {

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: UsernamePasswordToken =>
        Objects.equalsBuilder.add(principal, test.principal)
          .add(credential, test.credential).add(details, test.details)
          .isEquals
      case _ => false
    }
  }

  override def toString: String = {
    "principal:" + principal
  }

}

object AnonymousToken extends AuthenticationToken {

  def principal: Any = "anonymous"

  def credential: Any = ""

  override def addDetail(name: String, value: Any): Unit = {}

  override def removeDetail(name: String): Option[Any] = None

}

/**
 * Preauth Authentication Token
 */
class PreauthToken(val principal: Any, val credential: Any) extends AuthenticationToken {

  override def trusted: Boolean = {
    true
  }

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: PreauthToken =>
        Objects.equalsBuilder.add(principal, test.principal)
          .add(details, test.details).add(credential, test.credential).isEquals
      case _ => false
    }
  }

  override def toString: String = {
    principal.toString
  }
}
