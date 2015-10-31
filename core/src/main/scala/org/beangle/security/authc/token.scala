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
package org.beangle.security.authc

import java.security.Principal

import org.beangle.commons.lang.Objects

object DetailNames {
  val Agent = "agent"
  val Os = "os"
  val Server = "server"
  val Host = "host"
  val Timeout = "timeout"
}

/**
 * Authentication Token used before authentication
 */
trait AuthenticationToken extends Principal with Serializable {

  def principal: Any

  def credentials: Any

  def details: Map[String, Any]

  override def getName: String = {
    this.principal match {
      case jPrincipal: java.security.Principal => jPrincipal.getName
      case null => ""
      case obj: Any => obj.toString
    }
  }

  override def hashCode: Int = if (null == principal) 629 else principal.hashCode()
}

/**
 * Simple Authentication Token
 */
@SerialVersionUID(3966615358056184985L)
class UsernamePasswordAuthenticationToken(val principal: Any, val credentials: Any) extends AuthenticationToken {

  var details: Map[String, Any] = Map.empty

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: UsernamePasswordAuthenticationToken =>
        Objects.equalsBuilder.add(principal, test.principal)
          .add(credentials, test.credentials).add(details, test.details)
          .isEquals
      case _ => false
    }
  }

}

object AnonymousToken extends AuthenticationToken {

  def principal: Any = "anonymous"

  def credentials: Any = ""

  def details: Map[String, Any] = Map.empty

}
