package logger

import (
	"encoding/json"
	"os"
	"time"
)

var (
	fileWrite  *os.File
	fileAppend *os.File
	fileKPM    *os.File
	limitSizeAppendMB int64 = 10 // 10 MB
)

type KPMLogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Data      any    `json:"data"`
}

func InitCustomLogger(logPath string, limitSizeAppend int64) error {
	var err error

	if(limitSizeAppend > 0) {
		limitSizeAppendMB = limitSizeAppend
	}
	// File per scrittura (sovrascrive a ogni avvio)
	fileWrite, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	// File per append
	fileAppend, err = os.OpenFile(logPath+".log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	// File per KPM
	fileKPM, err = os.OpenFile(logPath+".kpm.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	return nil
}

func LogKPM_N3IWF_CONTEXT(data map[string]any) {

	entry := KPMLogEntry{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Message:   "N3IWF_CONTEXT",
		Data:      data,
	}

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		// Se fallisce la serializzazione, non scrive niente
		return
	}

	// Scrittura su file write
	if fileWrite != nil {
		//Svuoto il file prima di scrivere 
		if err := fileWrite.Truncate(0); err != nil {
			fileWrite.Close()
			fileWrite = nil
			return
		}
		if _, err := fileWrite.Seek(0, 0); err != nil {
			fileWrite.Close()
			fileWrite = nil
			return
		}
		fileWrite.Write(jsonBytes)
		fileWrite.Write([]byte("\n"))
	}

	// Scrittura su file append
	if fileAppend != nil {
		// Controllo dimensione file e lo resetto se supera il limite
		info, err := fileAppend.Stat()
		if err != nil {
			fileAppend.Close()
			fileAppend = nil
			return
		}
		if info.Size() >= limitSizeAppendMB*1024*1024 {
			if err := fileAppend.Truncate(0); err != nil {
				fileAppend.Close()
				fileAppend = nil
				return
			}
			if _, err := fileAppend.Seek(0, 0); err != nil {
				fileAppend.Close()
				fileAppend = nil
				return
			}
		}

		fileAppend.Write(jsonBytes)
		fileAppend.Write([]byte("\n"))
	}
}

func LogKPMMetrics(data any) {
	if fileKPM == nil {
		return
	}

	entry := KPMLogEntry{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Data:      data,
	}

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		// Se fallisce la serializzazione, non scrive niente
		return
	}

	// Scrittura su file KPM
	if err := fileKPM.Truncate(0); err != nil {
		fileKPM.Close()
		fileKPM = nil
		return
	}
	if _, err := fileKPM.Seek(0, 0); err != nil {
		fileKPM.Close()
		fileKPM = nil
		return
	}
	fileKPM.Write(jsonBytes)
	fileKPM.Write([]byte("\n"))
}
