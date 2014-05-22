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
   * Obtains the currently authenticated principal, or an authentication
   * request token.
   *
   * @return the <code>Authentication</code> or <code>null</code> if no
   *         authentication information is available
   */
  def authentication: AuthenticationInfo

  /**
   * Changes the currently authenticated principal, or removes the
   * authentication information.
   *
   * @param authentication
   *          the new <code>Authentication</code> token, or <code>null</code> if no further
   *          authentication information
   *          should be stored
   */
  def authentication_=(authentication: AuthenticationInfo)
}

/**
 * Base implementation of {@link SecurityContext}.
 * <p>
 * Used by default by {@link SecurityContextHolder}.
 * </p>
 *
 * @author chaostone
 * @version $Id: SecurityContextBean.java 2217 2007-10-27 00:45:30Z $
 */
@SerialVersionUID(3146265469090172129L)
class SecurityContextBean extends SecurityContext {

  var authentication: AuthenticationInfo = _

  override def equals(obj: Any): Boolean = {
    obj match {
      case sc: SecurityContext => authentication == sc.authentication
      case _ => false
    }
  }

  override def hashCode(): Int = if (authentication == null) -1 else authentication.hashCode()

  override def toString(): String = {
    val sb = new StringBuffer()
    sb.append(super.toString())

    if (authentication == null) sb.append(": Null authentication");
    else sb.append(": Authentication: ").append(authentication);

    sb.toString()
  }
}
