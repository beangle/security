package org.beangle.security.session.jdbc

import java.io.{InputStream, ObjectInputStream, Serializable => jSerializable}
import java.{util => ju}

import org.beangle.commons.event.EventPublisher
import org.beangle.commons.lang.Objects
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.authc.{Account, AuthenticationInfo}
import org.beangle.security.session.{AbstractSessionRegistry, DefaultSession, DefaultSessionProfile, LoginEvent, LogoutEvent, Session, SessionBuilder, SessionKey, SessionProfile}

class DBSessionRegistry(val builder: SessionBuilder, val executor: JdbcExecutor)
  extends AbstractSessionRegistry with EventPublisher {

  val columns = "id,account,principal,login_at,os,agent,host,server,expired_at,remark,timeout,last_access_at,last_accessed,category"

  val table = "se_sessoin_infoes"

  private def convert(datas: Seq[Seq[_]]): Seq[Session] = {
    for (data <- datas) yield convert(data)
  }

  private def convert(data: Seq[_]): Session = {
    val account = new ObjectInputStream(data(1).asInstanceOf[InputStream]).readObject().asInstanceOf[Account]
    val session = new DefaultSession(data(0).asInstanceOf[jSerializable], account, data(2).asInstanceOf[ju.Date], data(3).toString, data(4).toString, data(5).toString)
    session.server = data(6).toString
    session.expiredAt = if (null == data(7)) null else data(7).asInstanceOf[ju.Date]
    session.remark = if (null == data(8)) null else data(8).toString
    session.timeout = data(9).asInstanceOf[Number].shortValue()
    session.lastAccessAt = data(10).asInstanceOf[ju.Date]
    session.lastAccessed = if (null == data(11)) null else data(11).toString
    session
  }

  private def save(s: Session): Unit = {
    executor.update(s"insert into $table ($columns) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      s.id, s.principal.getName, s.loginAt, s.os, s.agent, s.host, s.server, s.expiredAt,
      s.remark, s.timeout, s.lastAccessAt, s.lastAccessed, category(s.principal))
  }

  override def register(info: AuthenticationInfo, key: SessionKey): Session = {
    val existed = get(key).orNull
    val principal = info.getName
    // 是否为重复注册
    if (null != existed && Objects.equals(existed.principal, principal)) {
      existed
    } else {
      // 争取名额
      tryAllocate(info, key)
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
      executor.update(s"delete from $table where id=?", key.sessionId)
    }
    s
  }

  override def onExpire(session: Session): Unit = {
    release(session)
    executor.update(s"update $table set expired_at=? where id=?", session.expiredAt, session.id) > 0
  }

  // FIXME update db to offen
  override def onAccess(session: Session, accessAt: ju.Date, accessed: String): Unit = {
    executor.update(s"update $table set last_access_at=? ,last_accessed=? where id=?", new ju.Date(accessed), accessed, session.id)
  }

  override def get(principal: String, includeExpired: Boolean): Seq[Session] = {
    convert(executor.query(s"select $columns from $table info where info.principal=?" +
      (if (!includeExpired) " and info.expired_at is null" else ""), principal))
  }

  /**
   * Get Expired and last accessed before the time
   */
  def getExpired(lastAccessAt: ju.Date): Seq[Session] = {
    convert(executor.query(s"select $columns from $table info where info.expired_at is not null or info.last_access_at <?", lastAccessAt))
  }

  def get(key: SessionKey): Option[Session] = {
    val datas = executor.query(s"select $columns from $table where id=?", key.sessionId)
    if (datas.isEmpty) None
    else Some(convert(datas.head))
  }

  def isRegisted(principal: String): Boolean = !executor.query(s"select id from $table where principal =?", principal).isEmpty

  def count: Int = executor.queryForInt(s"select count(id) from $table")

  protected override def allocate(auth: AuthenticationInfo, key: SessionKey): Boolean = {
    executor.update("update se_session_stats set on_line = on_line + 1 where on_line < capacity and category=?", category(auth)) > 0
  }

  protected override def release(session: Session): Unit = {
    executor.update("update se_session_stats set on_line=on_line - 1 where on_line>0 and category=?",
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
    executor.update(s"update se_session_stats stat set stat.on_line=(select count(id) from $table " +
      " info where info.expired_at is null and info.category=stat.category)");
  }

  @inline
  private def category(auth: AuthenticationInfo): Any = auth.principal.asInstanceOf[Account].category

}
