package logger

import (
	"encoding/json"
	"os"
)

var (
	fileRC *os.File
)

type RCLogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Data      any    `json:"data"`
}

func InitRCLogger(logPath string) error {
	var err error

	// File per RC
	fileRC, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	return nil
}

func LogRCMetrics(data any) {
	if fileRC == nil {
		return
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		// Se fallisce la serializzazione, non scrive niente
		return
	}

	// Scrittura su file RC
	if err := fileRC.Truncate(0); err != nil {
		fileRC.Close()
		fileRC = nil
		return
	}
	if _, err := fileRC.Seek(0, 0); err != nil {
		fileRC.Close()
		fileRC = nil
		return
	}
	fileRC.Write(jsonBytes)
	fileRC.Write([]byte("\n"))
}
