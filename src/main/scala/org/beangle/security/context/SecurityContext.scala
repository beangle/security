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

package org.beangle.security.context

import org.beangle.commons.lang.ScopedContext
import org.beangle.commons.security.Request
import org.beangle.security.session.Session

object SecurityContext {
  val Anonymous = "anonymous"

  private val key = ScopedContext.Key[SecurityContext]("beangle.security.context")

  def clear(): Unit = {
    ScopedContext.remove(key)
  }

  def set(ctx: SecurityContext): Unit = {
    ScopedContext.put(key, ctx)
  }

  def get: SecurityContext = {
    ScopedContext.get(key).get
  }
}

class SecurityContext(val session: Option[Session], val request: Request, val root: Boolean, val runAs: Option[String]) {

  def isValid: Boolean = {
    session.isDefined
  }
}

