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

package org.beangle.security.authc

object Profile {
  val AllValue = "*"
}

case class Profile(id: Long, name: String, properties: Map[String, String]) {

  def getProperty(key: String): Option[String] = {
    properties.get(key)
  }

  override def toString: String = {
    toJson
  }

  def toJson: String = {
    val props = new StringBuilder
    if (properties.isEmpty) {
      props ++= "{}"
    } else {
      props.append("{")
      properties foreach { case (k, v) =>
        props ++= s""""$k":"$v","""
      }
      props.setCharAt(props.length - 1, '}')
    }
    s"""{"id":${id},"name":"$name","properties":$props}"""
  }
}
