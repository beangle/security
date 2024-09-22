import org.beangle.parent.Dependencies.*
import org.beangle.parent.Settings.*

ThisBuild / organization := "org.beangle.security"
ThisBuild / version := "4.3.23-SNAPSHOT"

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

val beangle_commons = "org.beangle.commons" % "beangle-commons" % "5.6.18"
val beangle_jdbc = "org.beangle.jdbc" % "beangle-jdbc" % "1.0.3"
val beangle_serializer = "org.beangle.serializer" % "beangle-serializer" % "0.1.11"
val beangle_cache = "org.beangle.cache" % "beangle-cache" % "0.1.10"
val beangle_web = "org.beangle.web" % "beangle-web" % "0.5.0"

lazy val root = (project in file("."))
  .settings(
    name := "beangle-security",
    common,
    Compile / mainClass := Some("org.beangle.security.realm.ldap.Main"),
    libraryDependencies ++= Seq(beangle_commons, logback_classic % "test", scalatest, mockito),
    libraryDependencies ++= Seq(beangle_cache, beangle_jdbc, beangle_serializer),
    libraryDependencies ++= Seq(beangle_web, protobuf)
  )
