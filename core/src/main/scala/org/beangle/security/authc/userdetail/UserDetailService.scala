package org.beangle.security.authc.userdetail

trait UserDetailService {

  def loadDetail(principle: String): UserDetail
}
