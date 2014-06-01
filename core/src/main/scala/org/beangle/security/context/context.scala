/*
 * Beangle, Agile Java/Scala Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2013, Beangle Software.
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
package org.beangle.security.context

import org.beangle.security.authc.AuthenticationInfo
import org.beangle.security.session.Session
import org.beangle.security.mgt.SecurityManager

object SecurityContext {
  val Anonymous = "anonymous"
}
/**
 * Interface defining the minimum security information associated with the
 * current thread of execution.
 * <p>
 * The security context is stored in a {@link SecurityContextHolder}.
 * </p>
 *
 * @author chaostone
 */
trait SecurityContext extends Serializable {

  /**
   * Obtains the currently authenticated principal
   */
  def principal: Any

  def anthenticated: Boolean = null != session

  def session: Session

}

/**
 * Base implementation of {@link SecurityContext}.
 * <p>
 * Used by default by {@link SecurityContextHolder}.
 * </p>
 *
 * @author chaostone
 */
@SerialVersionUID(3146265469090172129L)
class SecurityContextBean(val session: Session) extends SecurityContext {

  def principal = session.principal

  override def equals(obj: Any): Boolean = {
    obj match {
      case sc: SecurityContext => principal == sc.principal
      case _ => false
    }
  }

  override def hashCode(): Int = session.hashCode()

  override def toString(): String = {
    val sb = new StringBuffer()
    sb.append(super.toString())

    if (principal == null) sb.append(": Null authentication");
    else sb.append(": principal: ").append(principal);

    sb.toString()
  }
}
