package org.beangle.security.session.jdbc

import java.{ util => ju }
import org.beangle.commons.event.EventPublisher
import org.beangle.commons.lang.Objects
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.authc.{ Account, AuthenticationInfo }
import org.beangle.security.session.{ DefaultSessionProfile, LoginEvent, LogoutEvent, Session, SessionBuilder, SessionException, SessionKey, SessionProfile, SessionRegistry }
import org.beangle.security.session.OvermaxSessionException
import org.beangle.security.session.AbstractSessionRegistry

class SessionStat(val category: String) {

  var capacity: Int = _

  var online: Int = _

  var statAt = new ju.Date();

}

class DBSessionRegistry(val builder: SessionBuilder, val executor: JdbcExecutor)
  extends AbstractSessionRegistry with EventPublisher {

  val all = ""

  private def convert(datas: Seq[Seq[_]]): List[Session] = {
    List()
  }

  private def convert(data: Seq[_]): Session = {
    null
  }

  private def update(session: Session): Unit = {

  }

  private def save(session: Session): Unit = {

  }
  override def register(info: AuthenticationInfo, key: SessionKey): Session = {
    val existed = get(key).orNull
    val principal = info.getName
    // 是否为重复注册
    if (null != existed && Objects.equals(existed.principal, principal)) {
      existed
    } else {
      // 争取名额
      val success = allocate(info, key)
      if (!success) throw new OvermaxSessionException(getMaxSession(info), info)
      // 注销同会话的其它账户
      if (null != existed) remove(key, " expired with replacement.");
      // 新生
      val session = builder.build(info, key)
      save(session);
      publish(new LoginEvent(session))
      session
    }
  }

  override def remove(key: SessionKey): Option[Session] = remove(key, null)

  private def remove(key: SessionKey, reason: String): Option[Session] = {
    val s = get(key)
    s foreach { session =>
      release(session)
      session.remark(reason)
      publish(new LogoutEvent(session))
      executor.update("delete from se_session_infoes where id=?", key.sessionId)
    }
    s
  }

  override def onExpire(session: Session): Unit = {
    release(session)
    executor.update("update se_session_infoes set expired_at=? where id=?", session.expiredAt, session.id) > 0
  }

  // FIXME update db to offen
  override def onAccess(session: Session, accessAt: ju.Date, accessed: String): Unit = {
    executor.update("update se_session_infoes set last_access_at=? ,last_accessed=? where id=?", new ju.Date(accessed), accessed, session.id)
  }

  override def get(principal: String, includeExpired: Boolean): List[Session] = {
    convert(executor.query(s"select $all from se_session_infoes info where info.principal=?" +
      (if (!includeExpired) " and info.expired_at is null" else ""), principal))
  }

  /**
   * Get Expired and last accessed before the time
   */
  def getExpired(lastAccessAt: ju.Date): Seq[Session] = {
    convert(executor.query(s"select $all from se_session_infoes info where info.expired_at is not null or info.last_access_at <?", lastAccessAt))
  }

  def get(key: SessionKey): Option[Session] = {
    val datas = executor.query("select * from se_session_infoes where id=?", key.sessionId)
    if (datas.isEmpty) None
    else Some(convert(datas.head))
  }

  def isRegisted(principal: String): Boolean = !executor.query("select id from se_sessoin_infoes where principal =?", principal).isEmpty

  def count: Int = executor.queryForInt("select count(*) from se_sessoin_infoes")

  @inline
  private def category(auth: AuthenticationInfo): Any = auth.principal.asInstanceOf[Account].category

  protected override def doAllocate(auth: AuthenticationInfo): Boolean = {
    executor.update("update se_session_stats set on_line = on_line + 1 where on_line < capacity and category=?", category(auth)) > 0
  }

  protected override def release(session: Session): Unit = {
    executor.update("update se_session_stats set on_line=on_line -1 where on_line>0 and category=?",
      category(session.principal.asInstanceOf[AuthenticationInfo]))
  }

  override def getProfile(auth: AuthenticationInfo): Option[SessionProfile] = {
    val rs = executor.query("select category,capacity,max_session,timeout from se_session_profiles  where category=?", category(auth))
    if (rs.isEmpty) None
    else {
      val data = rs(0)
      val profile = new DefaultSessionProfile(data(0).toString)
      profile.capacity = data(0).asInstanceOf[Number].intValue
      profile.maxSession = data(1).asInstanceOf[Number].intValue
      profile.timeout = data(2).asInstanceOf[Number].shortValue
      Some(profile)
    }
  }

  override def stat(): Unit = {
    executor.update("update se_session_stats stat set stat.on_line=(select count(*) from se_session_infoes " +
      " info where info.expired_at is null and info.category=stat.category)");
  }

}
