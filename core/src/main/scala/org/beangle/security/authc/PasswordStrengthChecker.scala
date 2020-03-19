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

object PasswordStrengthChecker {

  def check(password: String, policy: PasswordPolicy): Boolean = {
    if (Strings.isEmpty(password) || password.length < policy.minlen) {
      return false
    }

    var numCredit = 0
    var lowCredit = 0
    var upCredit = 0
    var otherCredit = 0
    val chars = password.toCharArray
    chars foreach { c =>
      if ('A' <= c && c <= 'Z') {
        upCredit += 1
      } else if ('0' <= c && c <= '9') {
        numCredit += 1
      } else if ('a' <= c && c <= 'z') {
        lowCredit += 1
      } else if ((33 <= c && c <= 47) || (58 <= c && c <= 64)) {
        otherCredit += 1
      }
    }
    if (policy.dcredit > numCredit ||
      policy.lcredit > lowCredit ||
      policy.ucredit > upCredit ||
      policy.ocredit > otherCredit) {
      return false
    }

    var clazz = 0
    if (upCredit > 0) clazz += 1
    if (numCredit > 0) clazz += 1
    if (otherCredit > 0) clazz += 1
    if (lowCredit > 0) clazz += 1

    policy.minclass <= clazz
  }
}
