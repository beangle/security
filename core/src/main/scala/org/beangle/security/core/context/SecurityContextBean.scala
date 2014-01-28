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
package org.beangle.security.core.context;

import org.beangle.security.core.Authentication

/**
 * Base implementation of {@link SecurityContext}.
 * <p>
 * Used by default by {@link SecurityContextHolder}.
 * </p>
 * 
 * @author chaostone
 * @version $Id: SecurityContextImpl.java 2217 2007-10-27 00:45:30Z $
 */
@SerialVersionUID(3146265469090172129L)
class SecurityContextBean extends SecurityContext {

  var authentication:Authentication = _

  override def equals(obj:Any) :Boolean={
    obj match {
      case sc:SecurityContext=> this.authentication==sc.authentication
      case _ => false
    }
  }


  override def  hashCode():Int= {
    if (this.authentication == null) {
      return -1;
    } else {
      return this.authentication.hashCode();
    }
  }

  override def toString():String = {
    val sb = new StringBuffer();
    sb.append(super.toString());

    if (this.authentication == null) {
      sb.append(": Null authentication");
    } else {
      sb.append(": Authentication: ").append(this.authentication);
    }

    sb.toString()
  }
}
