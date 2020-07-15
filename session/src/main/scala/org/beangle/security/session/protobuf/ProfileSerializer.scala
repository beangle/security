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
package org.beangle.security.session.protobuf

import java.io.{InputStream, OutputStream}

import org.beangle.commons.collection.Collections
import org.beangle.commons.io.ObjectSerializer
import org.beangle.security.authc.Profile

object ProfileSerializer extends ObjectSerializer {

  def toMessage(profile: Profile): Model.Profile = {
    val builder = Model.Profile.newBuilder()
    builder.setId(profile.id)
    builder.setName(profile.name)
    profile.properties foreach {
      case (k, v) =>
        builder.putProperties(k, v)
    }
    builder.build()
  }

  def fromMessage(mp: Model.Profile): Profile = {
    val temp = Collections.newMap[String, String]
    val i = mp.getPropertiesMap.entrySet().iterator()
    while (i.hasNext) {
      val e = i.next()
      temp.put(e.getKey, e.getValue)
    }
    Profile(mp.getId, mp.getName, temp.toMap)
  }

  override def serialize(data: Any, os: OutputStream, params: Map[String, Any]): Unit = {
    toMessage(data.asInstanceOf[Profile]).writeTo(os)
  }

  override def deserialize(is: InputStream, params: Map[String, Any]): Any = {
    fromMessage(Model.Profile.parseFrom(is))
  }
}
