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
package org.beangle.security.authc

object PasswordPolicy {

  case class PolicyBean(minlen: Int, dcredit: Int, lcredit: Int, ucredit: Int, ocredit: Int, minclass: Int) extends PasswordPolicy

  val Weak = PolicyBean(6, 0, 0, 0, 0, 1)
  val Medium = PolicyBean(8, 0, 0, 0, 0, 2)
  val Strong = PolicyBean(8, 0, 0, 0, 0, 3)
}

trait PasswordPolicy {

  /** 密码的最小长度 */
  def minlen: Int

  /** 密码中最少含有多少个数字 */
  def dcredit: Int

  /** 密码中最少含有多少个小写字母 */
  def lcredit: Int

  /** 密码中最少含有多少个大写字母 */
  def ucredit: Int

  /** 密码中最少含有多少个其他字母 */
  def ocredit: Int

  /** 密码中最少含有几类字符 */
  def minclass: Int

}
