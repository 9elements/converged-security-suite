package tools

import (
	log "github.com/sirupsen/logrus"
)

// ShowVersion shows progam version
func ShowVersion(toolName, tag, commit string) {
	log.Infof("%s %s", toolName, tag)
	log.Info("")
	log.Infof("Build Commit: %s", commit)
	log.Info("License: BSD 3-Clause License")
	log.Info("")
	log.Info("Copyright (c) 2020, 9elements GmbH.")
	log.Info("Copyright (c) 2020, facebook Inc.")
	log.Info("All rights reserved.")
}
