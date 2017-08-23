package org.beangle.security.protobuf

import java.io.{ InputStream, OutputStream }
import java.time.Instant

import org.beangle.commons.io.ObjectSerializer
import org.beangle.security.session.DefaultSession

object SessionSerializer extends ObjectSerializer {

  override def serialize(data: Any, os: OutputStream, params: Map[String, Any]): Unit = {
    val session = data.asInstanceOf[DefaultSession]
    val builder = Model.Session.newBuilder()
    builder.setId(session.id)
    builder.setPrincipal(AccountSerializer.toMessage(session.principal))
    builder.setLoginAt(session.loginAt.getEpochSecond)
    builder.setLastAccessAt(session.lastAccessAt.getEpochSecond)
    builder.build().writeTo(os)
  }

  override def deserialize(is: InputStream, params: Map[String, Any]): Any = {
    val s = Model.Session.parseFrom(is)
    val session = new DefaultSession(s.getId, AccountSerializer.fromMessage(s.getPrincipal),
      Instant.ofEpochSecond(s.getLoginAt))
    session.lastAccessAt = Instant.ofEpochSecond(s.getLastAccessAt)
    session
  }
}