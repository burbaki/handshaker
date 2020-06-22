name := "handshaker"

version := "0.1"

scalaVersion := "2.13.2"
libraryDependencies += "org.scodec" %% "scodec-bits" % "1.1.16"
libraryDependencies += "org.scodec" %% "scodec-core" % "1.11.16"
libraryDependencies += "dev.zio" %% "zio" % "1.0.0-RC20"
libraryDependencies += "dev.zio" %% "zio-streams" % "1.0.0-RC20"
libraryDependencies += "org.scalactic" %% "scalactic" % "3.2.0"
libraryDependencies += "org.scalatest" %% "scalatest" % "3.2.0" % "test"