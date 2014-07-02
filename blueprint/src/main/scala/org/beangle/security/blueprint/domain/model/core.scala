package org.beangle.security.blueprint.domain.model

import org.beangle.data.model.bean.{ CodedBean, EnabledBean, HierarchicalBean, IntIdBean, LongIdBean, NamedBean, NumIdBean, StringIdBean, TemporalOnBean, UpdatedBean }
import org.beangle.security.blueprint.domain.{ Field, Member }
import org.beangle.security.blueprint.domain.{ Profile, Role, User, UserProfile }
import org.beangle.security.blueprint.domain.Member.Ship.{ IsGranter, IsManager, IsMember, Ship }
import org.beangle.security.session.SessionProfile
import org.beangle.security.blueprint.domain.UserCategory
import java.{ util => ju }
import org.beangle.security.authz.Authority
import org.beangle.security.authz.GrantedAuthority
class FieldBean extends IntIdBean with NamedBean with Field {
  var title: String = _
  var source: String = _
  var multiple: Boolean = _
  var required: Boolean = _
  var typeName: String = _
  var keyName: String = _
  var properties: String = _
}

class UserCategoryBean extends IntIdBean with NamedBean with UserCategory {

}

class UserBean extends LongIdBean with CodedBean with NamedBean with UpdatedBean with TemporalOnBean with EnabledBean with User {
  var email: String = _
  var creator: Option[User] = None
  var credentialExpiredAt: Option[ju.Date] = None
  var members:collection.mutable.Seq[Member] = new collection.mutable.ListBuffer[Member]
  var credential: String = _
  var category: UserCategory = _
  var locked: Boolean = _

  def accountExpired: Boolean = {
    null != endOn && (new ju.Date).after(endOn)
  }

  def credentialExpired: Boolean = {
    credentialExpiredAt match {
      case Some(date) => (new ju.Date).after(date)
      case None => false
    }
  }

  def roles: Seq[Role] = {
    for (m <- members if m.member) yield m.role
  }

  def authorities: Seq[Authority] = {
    for (m <- members if m.member) yield new GrantedAuthority(m.role.id)
  }

  override def getName: String = {
    name
  }
}

class UserProfileBean extends LongIdBean with UserProfile {
  var user: User = _
  var properties = new collection.mutable.HashMap[Field, String]
}

class RoleBean extends IntIdBean with NamedBean with UpdatedBean with EnabledBean with HierarchicalBean[Role] with Profile with Role {
  var properties = new collection.mutable.HashMap[Field, String]
  var creator: Option[User] = None
  var members:collection.mutable.Seq[Member] = new collection.mutable.ListBuffer[Member]
  var remark: String = _
  override def getName: String = {
    name
  }
  def this(id: Int, name: String) {
    this()
    this.id = id
    this.name = name
  }
}

class MemberBean extends LongIdBean with UpdatedBean with Member {
  var user: User = _
  var role: Role = _
  var member: Boolean = _
  var granter: Boolean = _
  var manager: Boolean = _

  import Member.Ship._
  def is(ship: Ship): Boolean = {
    ship match {
      case IsMember => member
      case IsManager => manager
      case IsGranter => granter
      case _ => false
    }
  }
}

class SessionProfileBean extends StringIdBean with SessionProfile {
  var category: String = _
  var capacity: Int = _
  var maxSession: Int = _
  var timeout: Short = _
}