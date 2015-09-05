package org.beangle.security.session.jdbc

import java.io.{ InputStream, ObjectInputStream }
import java.io.{ ByteArrayInputStream, ByteArrayOutputStream }
import java.{ util => ju }
import org.beangle.commons.event.EventPublisher
import org.beangle.commons.lang.Objects
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.authc.Account
import org.nustaq.serialization.FSTConfiguration
import org.beangle.security.authc.DefaultAccount
import org.beangle.security.session.SessionKey
import org.beangle.security.session.LogoutEvent
import org.beangle.security.session.profile.ProfiledSessionRegistry
import org.beangle.security.session.profile.SessionProfile
import org.beangle.security.session.LoginEvent
import org.beangle.security.session.DefaultSession
import org.beangle.security.session.profile.DefaultSessionProfile
import org.beangle.security.session.Session
import org.beangle.security.session.SessionBuilder
import org.beangle.security.session.SessionId
import org.beangle.security.session.profile.ProfileChangeEvent
import org.beangle.commons.bean.Initializing
import org.beangle.security.session.SessionCleaner
import org.beangle.security.session.SessionCleanupDaemon
import java.util.Timer

/**
 * 基于数据库的session注册表
 */
class DBSessionRegistry(val builder: SessionBuilder, val executor: JdbcExecutor)
    extends ProfiledSessionRegistry with EventPublisher with Initializing {

  private val fstconf = FSTConfiguration.createDefaultConfiguration();

  private val insertColumns = "id,principal,login_at,os,agent,host,server,expired_at,timeout,last_access_at,last_accessed,profile_id,principal_name"

  private val selectColumns = "id,principal,login_at,timeout,server,expired_at,last_access_at,last_accessed"

  var sessionTable = "session_infoes"

  var statTable = "session_stats"

  var accessDelayMillis = 5000

  var cleaner: SessionCleaner = _

  def init() {
    val exists = executor.query(s"select id from $statTable").map(x => x.head.asInstanceOf[Number]).toSet
    profileProvider.getProfiles() foreach { p =>
      if (exists.contains(p.id.longValue())) {
        executor.update(s"update $statTable set capacity=? where id=?", p.capacity, p.id.longValue())
      } else {
        executor.update(s"insert into $statTable(id,on_line,capacity,stat_at) values(?,?,?,?)", p.id.longValue, 0, p.capacity, new ju.Date)
      }
    }
    if (null != cleaner) {
      // 下一次间隔开始清理，不浪费启动时间
      new Timer("Beangle Session Cleaner", true).schedule(new SessionCleanupDaemon(cleaner),
        new ju.Date(System.currentTimeMillis() + cleaner.cleanIntervalMillis),
        cleaner.cleanIntervalMillis);
    }
  }

  override def register(info: Account, key: SessionKey): Session = {
    val existed = get(key).orNull
    val principal = info.getName
    // 是否为重复注册
    if (null != existed && Objects.equals(existed.principal, principal)) {
      existed
    } else {
      tryAllocate(key, info) // 争取名额
      if (null != existed) remove(key, " expired with replacement."); // 注销同会话的其它账户
      val session = builder.build(key, info, this, new ju.Date, getTimeout(info)) // 新生
      save(session)
      publish(new LoginEvent(session))
      session
    }
  }

  override def remove(key: SessionKey): Option[Session] = remove(key, null)

  override def expire(session: Session): Unit = {
    release(session)
    executor.update(s"update $sessionTable set expired_at=? where id=?", session.expiredAt, session.id) > 0
  }

  override def access(session: Session, accessAt: ju.Date, accessed: String): Unit = {
    if (accessAt.getTime - session.lastAccessAt.getTime > accessDelayMillis) {
      executor.update(s"update $sessionTable set last_access_at=? ,last_accessed=? where id=?", accessAt, accessed, session.id)
    }
  }

  override def get(principal: String, includeExpired: Boolean): Seq[Session] = {
    convert(executor.query(s"select $selectColumns from $sessionTable info where info.principal_name=?" +
      (if (!includeExpired) " and info.expired_at is null" else ""), principal))
  }

  /**
   * Get Expired and last accessed before the time
   */
  def getExpired(lastAccessAt: ju.Date): Seq[Session] = {
    convert(executor.query(s"select $selectColumns from $sessionTable info where info.expired_at is not null or info.last_access_at <?", lastAccessAt))
  }

  def get(key: SessionKey): Option[Session] = {
    val datas = executor.query(s"select $selectColumns from $sessionTable where id=?", key.sessionId)
    if (datas.isEmpty) None else Some(convert(datas.head))
  }

  def isRegisted(principal: String): Boolean = {
    !executor.query(s"select id from $sessionTable where principal =?", principal).isEmpty
  }

  def count: Int = {
    executor.queryForInt(s"select count(id) from $sessionTable")
  }

  protected override def allocate(auth: Account, key: SessionKey): Boolean = {
    executor.update(s"update $statTable set on_line = on_line + 1 where on_line < capacity and id=?", getProfileId(auth).longValue()) > 0
  }

  protected override def release(session: Session): Unit = {
    executor.update(s"update $statTable set on_line=on_line - 1 where on_line>0 and id=?", getProfileId(session.principal).longValue())
  }

  override def stat(): Unit = {
    executor.update(s"update $statTable stat set on_line=(select count(id) from $sessionTable " +
      " info where info.expired_at is null and info.profile_id=stat.id),stat_at = ?", new ju.Date());
  }
  /**
   * Handle an application event.
   */
  override def onEvent(event: ProfileChangeEvent): Unit = {
    executor.update(s"update $statTable set capacity=? where id=?", event.profile.id.longValue())
  }

  private def convert(datas: Seq[Seq[_]]): Seq[Session] = {
    for (data <- datas) yield convert(data)
  }

  private def remove(key: SessionKey, reason: String): Option[Session] = {
    val s = get(key)
    s foreach { session =>
      release(session)
      publish(new LogoutEvent(session, reason))
      executor.update(s"delete from $sessionTable where id=?", key.sessionId)
    }
    s
  }

  private def convert(data: Seq[_]): Session = {
    val account = data(1) match {
      case is: InputStream => new ObjectInputStream(is).readObject().asInstanceOf[Account]
      case ba: Array[Byte] => fstconf.asObject(ba).asInstanceOf[DefaultAccount]
    }
    val loginAt = data(2).asInstanceOf[ju.Date]
    val timeout = data(3).asInstanceOf[Number].shortValue()
    val session = builder.build(SessionId(data(0).toString()), account, this, loginAt, timeout).asInstanceOf[DefaultSession]
    session.server = if (null == data(4)) null else data(4).toString
    session.expiredAt = if (null == data(5)) null else data(5).asInstanceOf[ju.Date]
    session.lastAccessAt = data(6).asInstanceOf[ju.Date]
    session.lastAccessed = if (null == data(7)) null else data(7).toString
    session
  }

  private def save(s: Session): Unit = {
    executor.update(s"insert into $sessionTable ($insertColumns) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
      s.id, fstconf.asByteArray(s.principal), s.loginAt, s.os, s.agent, s.host, s.server, s.expiredAt,
      s.timeout, s.lastAccessAt, s.lastAccessed, profileProvider.getProfile(s.principal).id.longValue(), s.principal.getName)
  }

}
