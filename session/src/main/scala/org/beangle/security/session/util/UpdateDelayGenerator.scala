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
package org.beangle.security.session.util

/**
 * @author chaostone
 * 随机产生更新时间间隔，单位毫秒数（默认在60s到120s之间）
 */
class UpdateDelayGenerator(val minDelay: Int = 60 , val maxDelay: Int = 120 ) {

  def generateDelaySeconds(): Int = {
    val d = new scala.util.Random(System.currentTimeMillis).nextDouble()
    ((d * (maxDelay - minDelay)) + minDelay).asInstanceOf[Int]
  }
}
