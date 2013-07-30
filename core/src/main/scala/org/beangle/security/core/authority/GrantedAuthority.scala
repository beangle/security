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
package org.beangle.security.core.authority

import org.beangle.commons.lang.Assert
import org.beangle.security.core.Authority

/** Basic concrete implementation of a {@link Authority}. */
@SerialVersionUID(1L)
class GrantedAuthority(val role:Any) extends Authority with Serializable   {

  Assert.notNull(role, "A granted authority textual representation is required")

  def authority:Any=role

  override def equals(obj:Any) :Boolean  = {
    obj match{
      case ga:GrantedAuthority => ga.role == this.role
      case _ => false
    }
  }

  override def hashCode():Int = role.hashCode

  override def toString():String = role.toString

  def compare(o:Authority):Int= {
    if (o != null) {
      o.authority  match{
        case or:Ordered[Any] => or compare role
        case comp:java.lang.Comparable[Any] => comp compareTo role
        case _ =>
          throw new RuntimeException("Cannot compare GrantedAuthority using role:" + role)
      }
    }else -1
  }
}
