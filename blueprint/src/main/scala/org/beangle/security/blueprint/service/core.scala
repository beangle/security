package org.beangle.security.blueprint.service

import org.beangle.security.blueprint.domain.{ Member, Role, User }
import org.beangle.security.blueprint.domain.Profile
import org.beangle.security.blueprint.domain.FuncResource
import org.beangle.security.blueprint.domain.Field

trait UserService {

  def get(code: String): Option[User]

  def get(id: Long): Option[User]

  def saveOrUpdate(user: User)

  def getUsers(id: Long*): Seq[User]

  def getMembers(user: User, ship: Member.Ship.Ship): Seq[Member]

  def updateState(manager: User, newUser: User): Unit

  def create(creator: User, newUser: User): Unit

  def remove(creator: User, user: User): Unit

  def isManagedBy(manager: User, user: User): Boolean

  def isRoot(user: User): Boolean
}

trait RoleService {

  def get(id: Int): Role

  def create(creator: User, role: Role): Unit

  def move(role: Role, parent: Role, indexno: Int): Unit

  def remove(manager: User, roles: Seq[Role]): Unit

  def isManagedBy(manager: User, role: Role): Boolean

  def orphans: Seq[Role]
}

trait ProfileService {

  def getProfiles(user: User, resource: FuncResource): Seq[Profile]

  def getFieldValues(field: Field, keys: Any*): Seq[Any]

  def getField(fieldName: String): Field

  def get(id: Long): Profile

}
