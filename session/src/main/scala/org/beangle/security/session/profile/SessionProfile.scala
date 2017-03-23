/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
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
package org.beangle.security.session.profile

import org.beangle.commons.lang.Objects
import org.beangle.security.session.Session

/**
 * Session Profile
 */
trait SessionProfile {
  def id: Int
  def capacity: Int
  def maxSession: Int
  def timeout: Short
}

object DefaultSessionProfile extends DefaultSessionProfile(1) {
  this.capacity = Int.MaxValue
  this.maxSession = -1
  this.timeout = Session.DefaultTimeOut
}

class DefaultSessionProfile(val id: Int) extends SessionProfile {
  var capacity: Int = _
  var maxSession: Int = _
  var timeout: Short = _

  override def toString(): String = {
    Objects.toStringBuilder(this).add("id", id)
      .add("capacity", capacity).add("maxSession", maxSession)
      .add("timeout", timeout).toString
  }
}
