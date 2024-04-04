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

package org.beangle.security.authz

import org.beangle.commons.bean.Refreshable
import org.beangle.commons.security.Request
import org.beangle.security.context.SecurityContext

trait Authorizer extends Refreshable {

  final def isPermitted(context: SecurityContext): Boolean = {
    isPermitted(context, context.request)
  }

  def isPermitted(context: SecurityContext, request: Request): Boolean

  def isRoot(user: String): Boolean

}

object PublicAuthorizer extends Authorizer {
  def isPermitted(context: SecurityContext, request: Request): Boolean = {
    true
  }

  def isRoot(user: String): Boolean = {
    false
  }

  override def refresh(): Unit = {}
}

object ProtectedAuthorizer extends Authorizer {
  def isPermitted(context: SecurityContext, request: Request): Boolean = {
    context.isValid
  }

  def isRoot(user: String): Boolean = {
    false
  }

  override def refresh(): Unit = {}
}
