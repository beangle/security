package org.beangle.security.session.util

/**
 * @author chaostone
 * 随机产生更新时间间隔，单位毫秒数（默认在30s到10分钟之间）
 */
class UpdadateDelayGenerator(minDelay: Int = 30 * 1000, maxDelay: Int = 600 * 1000) {

  def generateDelayMilliTime(): Int = {
    val d = new scala.util.Random(System.currentTimeMillis).nextDouble
    ((d * (maxDelay - minDelay)) + minDelay).asInstanceOf[Int]
  }
}
