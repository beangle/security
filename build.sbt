import org.beangle.parent.Dependencies.*
import org.beangle.parent.Settings.*

ThisBuild / organization := "org.beangle.security"
ThisBuild / version := "4.3.19"

ThisBuild / scmInfo := Some(
  ScmInfo(
    url("https://github.com/beangle/security"),
    "scm:git@github.com:beangle/security.git"
  )
)

ThisBuild / developers := List(
  Developer(
    id = "chaostone",
    name = "Tihua Duan",
    email = "duantihua@gmail.com",
    url = url("http://github.com/duantihua")
  )
)

ThisBuild / description := "The Beangle Data Library"
ThisBuild / homepage := Some(url("https://beangle.github.io/security/index.html"))

val beangle_common_ver = "5.6.15"
val beangle_jdbc_ver = "1.0.0"
val beangle_web_ver = "0.4.11"
val beangle_serializer_ver = "0.1.9"
val beangle_cache_ver = "0.1.8"
val beangle_commons = "org.beangle.commons" % "beangle-commons" % beangle_common_ver
val beangle_jdbc = "org.beangle.jdbc" % "beangle-jdbc" % beangle_jdbc_ver
val beangle_serializer = "org.beangle.serializer" % "beangle-serializer" % beangle_serializer_ver

val beangle_cache = "org.beangle.cache" % "beangle-cache" % beangle_cache_ver
val beangle_web = "org.beangle.web" % "beangle-web" % beangle_web_ver
val commonDeps = Seq(beangle_commons, logback_classic, logback_core, scalatest, mockito)

lazy val root = (project in file("."))
  .settings(
    name := "beangle-security",
    common,
    libraryDependencies ++= commonDeps,
    libraryDependencies ++= Seq(beangle_cache, beangle_jdbc, beangle_serializer),
    libraryDependencies ++= Seq(beangle_web,protobuf)
  )
