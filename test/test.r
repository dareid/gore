require(Rserve)
source("test-functions.r")
packageVersion("Rserve")
run.Rserve(config.file="/etc/Rserv.conf")
