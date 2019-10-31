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

import org.beangle.commons.lang.Strings


trait PasswordStrengthChecker {
  def check(password: String): PasswordStrengths.Strength
}

object PasswordStrengths extends Enumeration(0) {

  class Strength(val description: String) extends super.Val {
  }

  private def value(n: String): Strength = {
    new Strength(n)
  }

  val VeryWeak = value("Very Weak")
  val Weak = value("Weak")
  val Medium = value("Medium")
  val Strong = value("Strong")
  val VeryStrong = value("Very Strong")
}

class DefaultPasswordStrengthChecker(minlength: Int) extends PasswordStrengthChecker {
  def check(password: String): PasswordStrengths.Strength = {
    if (Strings.isEmpty(password) || password.length < minlength) {
      return PasswordStrengths.VeryWeak
    }
    var hasCaps = false
    var hasNums = false
    var hasSpecials = false
    var hasLows = false
    val chars = password.toCharArray
    chars foreach { c =>
      if (!hasCaps && 'A' <= c && c <= 'Z') {
        hasCaps = true
      } else if (!hasNums && '0' <= c && c <= '9') {
        hasNums = true
      } else if (!hasLows && 'a' <= c && c <= 'z') {
        hasLows = true
      } else if (!hasSpecials && (33 <= c && c <= 47) || (58 <= c && c <= 64)) {
        hasSpecials = true
      }
    }
    var indicator = 0
    if (hasCaps) indicator += 1
    if (hasNums) indicator += 1
    if (hasSpecials) indicator += 1
    if (hasLows) indicator += 1

    PasswordStrengths(indicator).asInstanceOf[PasswordStrengths.Strength]
  }
}
