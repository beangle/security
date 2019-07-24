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
package org.beangle.security

import org.beangle.security.session.Session
import org.beangle.security.context.SecurityContext

object Securities {
  def session: Option[Session] = {
    SecurityContext.get.session
  }

  def user: String = {
    val context = SecurityContext.get
    context.session match {
      case None => SecurityContext.Anonymous
      case Some(session) =>
        if (context.root && context.runAs.isDefined) {
          context.runAs.get
        } else {
          session.principal.getName
        }
    }
  }

  def resource: String = {
    val context = SecurityContext.get
    context.request.resource.toString
  }

}
