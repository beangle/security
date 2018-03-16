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

import java.{ lang => jl }

import org.beangle.commons.lang.Assert

trait AuthorizationInfo {
  def authorities: Any
  def permissions: Any
}

/** Basic concrete implementation of a {@link Authority}. */
@SerialVersionUID(1L)
class Role(val name: Any) extends Serializable {

  Assert.notNull(name, "A granted authority textual representation is required")

  def authority: Any = name

  override def equals(obj: Any): Boolean = {
    obj match {
      case ga: Role => ga.name == this.name
      case _        => false
    }
  }

  override def hashCode(): Int = name.hashCode

  override def toString(): String = name.toString

  def compare(o: Role): Int = {
    if (o != null) {
      o.authority match {
        case or: Ordered[_]         => or.asInstanceOf[Ordered[Any]] compare name
        case comp: jl.Comparable[_] => comp.asInstanceOf[jl.Comparable[Any]] compareTo name
        case _ =>
          throw new RuntimeException("Cannot compare GrantedAuthority using role:" + name)
      }
    } else -1
  }
}
