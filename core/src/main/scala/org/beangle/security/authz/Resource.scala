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

object Resource {
  /** 资源的所有部分 */
  final val AllParts = "*"

  /** 允许所有操作 */
  final val AllActions = "*"
}

trait Resource extends Serializable {
  def title: String

  def actions: Option[String]

  def remark: Option[String]

  def name: String

  def enabled: Boolean
}

object Scopes extends Enumeration(0) {

  class Scope(name: String) extends super.Val(name)

  /** 不受保护的公共资源 */
  val Public: Scope = ScopeValue("Public")
  /** 受保护的公有资源 */
  val Protected: Scope = ScopeValue("Protected")
  /** 受保护的私有资源 */
  val Private: Scope = ScopeValue("Private")

  private def ScopeValue(name: String): Scope = {
    new Scope(name)
  }
}
