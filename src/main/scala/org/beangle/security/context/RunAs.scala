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

package org.beangle.security.context

import org.beangle.commons.json.{Json, JsonObject}
import org.beangle.security.authc.Profile

case class RunAs(name: String, profiles: Seq[Profile])

object RunAs {
  def parseJson(js: String): Option[RunAs] = {
    try {
      val json = Json.parseObject(js)
      if (json.contains("name")) {
        val name = json.getString("name")
        if (json.contains("profiles")) {
          val profiles = json.getArray("profiles")
          val ps = profiles.map { x =>
            val jo = x.asInstanceOf[JsonObject]
            Profile(jo.getLong("id"), jo.getString("name"), parseProperties(jo))
          }
          Some(RunAs(name, ps.toSeq))
        } else {
          Some(RunAs(name, Seq.empty))
        }
      } else {
        None
      }
    } catch {
      case _: Exception => None
    }
  }

  private def parseProperties(jo: JsonObject): Map[String, String] = {
    jo.get("properties") match {
      case Some(props: JsonObject) =>
        props.iterator.map { case (k, v) => k -> v.toString }.toMap
      case _ => Map.empty
    }
  }
}
