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

import java.io.Externalizable
import java.security.Principal

/**
 * Authentication Information
 *
 * @author chaostone
 */
trait Account extends Principal with Externalizable {

  def name: String

  def categoryId: Int

  def description: String

  def remoteToken: Option[String]

  def details: Map[String, Any]

  def accountExpired: Boolean

  def accountLocked: Boolean

  def credentialExpired: Boolean

  def disabled: Boolean

  def credentialReadOnly: Boolean

  def authorities: Array[String]

  def permissions: Array[String]

  def profiles: Array[Profile]

  def isRemote: Boolean

  override def hashCode: Int = {
    if (null == name) 629 else name.hashCode()
  }

  def getName: String = {
    name
  }

}
