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

package org.beangle.security.realm.cas

/** Cas 服务器的响应
 *
 * @param code       响应码
 * @param user       用户ID
 * @param attributes 属性
 * @param message    响应消息
 */
case class CasResponse(code: String, user: Option[String], attributes: Map[String, String], message: String) {

  def validated: Boolean = {
    user.nonEmpty
  }

  /** 获取响应中的账户名
   *
   * @param accountName 账户对应的属性名
   * @return
   */
  def getAccount(accountName: String): String = {
    user match {
      case None => null
      case Some(u) =>
        if (null == accountName || accountName == "user") {
          u
        } else {
          if attributes.contains(accountName) then attributes(accountName)
          else throw new IllegalArgumentException(s"CasResponse cannot recognize $accountName")
        }
    }
  }
}
