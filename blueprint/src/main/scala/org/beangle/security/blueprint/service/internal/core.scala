package org.beangle.security.blueprint.service.internal

import org.beangle.commons.codec.digest.Digests
import org.beangle.commons.lang.Strings
import org.beangle.data.jpa.dao.OqlBuilder
import org.beangle.data.model.dao.EntityDao
import org.beangle.security.authc.{ AbstractAccountRealm, Account, AccountStore, AuthenticationToken, BadCredentialsException, DefaultAccount }
import org.beangle.security.blueprint.domain.{ Member, User }
import org.beangle.security.blueprint.service.UserService

class UserServiceImpl(entityDao: EntityDao) extends UserService {
  def get(code: String): Option[User] = {
    if (Strings.isEmpty(code)) return null;
    val query = OqlBuilder.from(classOf[User], "user")
    query.where("user.code=:code", code)
    val users = entityDao.search(query)
    if (users.isEmpty) None else Some(users(0))
  }

  def get(id: Long): Option[User] = {
    entityDao.find(classOf[User], java.lang.Long.valueOf(id))
  }

  def saveOrUpdate(user: User): Unit = {

  }

  def getUsers(id: Long*): Seq[User] = {
    Seq.empty
  }

  def getMembers(user: User, ship: Member.Ship.Ship): Seq[Member] = {
    Seq.empty
  }

  def updateState(manager: User, newUser: User): Unit = {
  }

  def create(creator: User, newUser: User): Unit = {
  }

  def remove(creator: User, user: User): Unit = {
  }

  def isManagedBy(manager: User, user: User): Boolean = {
    true
  }

  def isRoot(user: User): Boolean = {
    true
  }
}

class DaoUserStore(userService: UserService) extends AccountStore {
  def load(principal: Any): Option[Account] = {
    userService.get(principal.toString) match {
      case Some(user) =>
        val account = new DefaultAccount(user.name, user.id)
        account.accountExpired = user.accountExpired
        account.accountLocked = user.locked
        account.credentialExpired = user.credentialExpired
        account.category = user.category.name
        account.disabled = !user.enabled
        account.authorities = user.authorities
        account.details += "credential" -> user.credential
        Some(account)
      case None => None
    }
  }
}

class DaoUserRealm(daoUserStore: DaoUserStore) extends AbstractAccountRealm {

  protected override def credentialsCheck(token: AuthenticationToken, account: Account): Unit = {
    val credential = account.details("credential")
    account.details = account.details - "credential"
    if (credential != Digests.md5Hex(token.credentials.toString)) throw new BadCredentialsException("Incorrect password", token, null)
  }

  protected override def loadAccount(principal: Any): Option[Account] = {
    daoUserStore.load(principal)
  }
}
