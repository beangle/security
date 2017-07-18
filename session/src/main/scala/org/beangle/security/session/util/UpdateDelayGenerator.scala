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
package org.beangle.security.session.util

/**
 * @author chaostone
 * 随机产生更新时间间隔，单位毫秒数（默认在30s到60s之间）
 */
class UpdateDelayGenerator(minDelay: Int = 30 , val maxDelay: Int = 60 ) {

  def generateDelaySeconds(): Int = {
    val d = new scala.util.Random(System.currentTimeMillis).nextDouble
    ((d * (maxDelay - minDelay)) + minDelay).asInstanceOf[Int]
  }
}
