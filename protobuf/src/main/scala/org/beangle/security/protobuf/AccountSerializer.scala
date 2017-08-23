package org.beangle.security.protobuf

import java.io.{ InputStream, OutputStream }

import org.beangle.commons.io.ObjectSerializer
import org.beangle.security.authc.DefaultAccount

object AccountSerializer extends ObjectSerializer {

  def toMessage(account: DefaultAccount): Model.Account = {
    val builder = Model.Account.newBuilder()
    builder.setName(account.name)
    builder.setDescription(account.description)
    builder.setStatus(account.status)
    account.remoteToken foreach { t =>
      builder.setRemoteToken(t)
    }
    if (null != account.authorities) builder.setAuthorities(account.authorities)
    if (null != account.permissions) builder.setPermissions(account.permissions)
    account.details foreach {
      case (k, v) =>
        builder.putDetails(k, v)
    }
    builder.build()
  }

  def fromMessage(pa: Model.Account): DefaultAccount = {
    val account = new DefaultAccount(pa.getName, pa.getDescription)
    account.status = pa.getStatus
    account.authorities = pa.getAuthorities
    account.permissions = pa.getPermissions
    account.remoteToken = Option(pa.getRemoteToken)
    val dk = pa.getDetailsMap.entrySet().iterator()
    while (dk.hasNext()) {
      val entry = dk.next()
      account.details += (entry.getKey -> entry.getValue)
    }
    account
  }

  override def serialize(data: Any, os: OutputStream, params: Map[String, Any]): Unit = {
    toMessage(data.asInstanceOf[DefaultAccount]).writeTo(os)
  }

  override def deserialize(is: InputStream, params: Map[String, Any]): Any = {
    fromMessage(Model.Account.parseFrom(is))
  }
}
