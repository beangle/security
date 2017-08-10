package org.beangle.security.authc

import java.io.{ ObjectInput, ObjectOutput }

import org.beangle.commons.collection.Collections
import org.beangle.commons.lang.Objects

object DefaultAccount {
  object StatusMask {
    val Locked = 1
    val Disabled = 2
    val AccountExpired = 4
    val CredentialExpired = 8
  }
}
import DefaultAccount.StatusMask._

final class DefaultAccount extends Account {

  var name: String = _

  var description: String = _

  var remoteToken: Option[String] = None

  var status: Int = _

  var authorities: String = _

  var permissions: String = _

  var details: Map[String, String] = Map.empty

  def this(name: String, description: String) {
    this()
    this.name = name
    this.description = description
  }

  private def change(value: Boolean, mask: Int): Unit = {
    if (value) status = status | mask
    else {
      if ((status & mask) > 0) status = status ^ mask
    }
  }

  private def get(mask: Int): Boolean = (status & mask) > 0

  def accountExpired: Boolean = get(AccountExpired)

  def accountExpired_=(value: Boolean) = change(value, AccountExpired)

  def accountLocked: Boolean = get(Locked)

  def accountLocked_=(locked: Boolean): Unit = change(locked, Locked)

  def credentialExpired: Boolean = get(CredentialExpired)

  def credentialExpired_=(expired: Boolean): Unit = change(expired, CredentialExpired)

  def disabled: Boolean = get(Disabled)

  def disabled_=(value: Boolean): Unit = change(value, Disabled)

  def addDetails(added: Map[String, Any]): Unit = {
    added foreach {
      case (a, b) =>
        details += (a -> b.toString)
    }
  }

  override def toString(): String = {
    Objects.toStringBuilder(this).add("Name:", name)
      .add("AccountExpired: ", accountExpired)
      .add("credentialExpired: ", credentialExpired)
      .add("AccountLocked: ", accountLocked)
      .add("Disabled: ", disabled)
      .add("Authorities: ", authorities)
      .add("Permissions: ", permissions).toString
  }

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: DefaultAccount => Objects.equalsBuilder.add(this.name, test.name).isEquals
      case _                    => false
    }
  }

  def writeExternal(out: ObjectOutput): Unit = {
    out.writeObject(name)
    out.writeObject(description)
    out.writeObject(remoteToken.orNull)
    out.writeInt(status)
    out.writeObject(authorities)
    out.writeObject(permissions)
    out.writeInt(details.size)
    details foreach {
      case (k, v) =>
        out.writeObject(k)
        out.writeObject(v)
    }
  }

  def readExternal(in: ObjectInput): Unit = {
    name = in.readObject.toString
    description = in.readObject.toString
    remoteToken = Option(in.readObject.asInstanceOf[String])
    status = in.readInt()
    authorities = in.readObject.asInstanceOf[String]
    permissions = in.readObject.asInstanceOf[String]
    val mapSize = in.readInt()
    val temp = Collections.newMap[String, String]
    (0 until mapSize) foreach { i =>
      val k = in.readObject.toString
      val v = in.readObject.toString
      temp += (k -> v)
    }
    details = temp.toMap
  }
}
