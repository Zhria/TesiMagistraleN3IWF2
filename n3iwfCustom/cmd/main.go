package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/urfave/cli/v2"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/internal/rc"
	"github.com/free5gc/n3iwf/internal/snapshot"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/free5gc/n3iwf/pkg/service"
	logger_util "github.com/free5gc/util/logger"
	"github.com/free5gc/util/version"
)

func main() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.MainLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	app := cli.NewApp()
	app.Name = "n3iwf"
	app.Usage = "Non-3GPP Interworking Function (N3IWF)"
	app.Action = action
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "Load configuration from `FILE`",
		},
		&cli.StringSliceFlag{
			Name:    "log",
			Aliases: []string{"l"},
			Usage:   "Output NF log to `FILE`",
		},
		&cli.BoolFlag{
			Name:    "nolog",
			Aliases: []string{"nl"},
			Usage:   "Disable log to stdout/stderr",
		},
		&cli.StringFlag{
			Name:    "loglevel",
			Aliases: []string{"ll"},
			Usage:   "Override logger level",
		},
		&cli.BoolFlag{
			Name:    "reportcaller",
			Aliases: []string{"rc"},
			Usage:   "Enable logger report caller",
		},
		&cli.BoolFlag{
			Name:    "debug",
			Aliases: []string{"deb"},
			Usage:   "Enable pprof debug",
		},
	}
	if err := app.Run(os.Args); err != nil {
		logger.MainLog.Errorf("N3IWF Run Error: %v\n", err)
	}
}

func runPProfServer() {
	r := gin.Default()
	pprof.Register(r)
	// Listen and Server in 0.0.0.0:6061
	err := r.Run(":6061")
	if err != nil {
		logger.MainLog.Errorf("runPProfServer(): %v", err)
	}
}

func action(cliCtx *cli.Context) error {
	debug := cliCtx.Bool("debug")
	if debug {
		go runPProfServer()
	}
	logPathSlice := cliCtx.StringSlice("log")
	cfgPath := cliCtx.String("config")
	noLog := cliCtx.Bool("nolog")
	logLevel := cliCtx.String("loglevel")
	reportCaller := cliCtx.Bool("reportcaller")

	tlsKeyLogPath, err := initLogFile(logPathSlice)
	if err != nil {
		return err
	}

	logger.MainLog.Infoln("N3IWF version: ", version.GetVersion())

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh  // Wait for interrupt signal to gracefully shutdown
		cancel() // Notify each goroutine and wait them stopped
	}()

	cfg, err := factory.ReadConfig(cfgPath)
	if err != nil {
		close(sigCh)
		return err
	}
	factory.N3iwfConfig = cfg

	// Replace logger config with cli parameters
	if noLog {
		cfg.SetLogEnable(false)
	}
	if logLevel != "" {
		cfg.SetLogLevel(logLevel)
	}
	if reportCaller {
		cfg.SetLogReportCaller(true)
	}

	n3iwfApp, err := service.NewApp(ctx, cfg, tlsKeyLogPath)
	if err != nil {
		close(sigCh)
		return err
	}

	logger.InitCustomLogger(factory.N3iwfE2DefaultLogPath, 100)
	logger.InitRCLogger("./log/n3iwf_e2_rc.json")

	go startSnapshot(n3iwfApp)

	//Avvio un altro thread per il kpm metrics logger.
	go startKPMLogger()
	rc.SetHandoverAlertHandler(rc.NewHandoverAlertHandler(n3iwfApp.Context(), n3iwfApp))
	rc.StartHandoverHTTPServer("")
	go startRCLogger(n3iwfApp)

	n3iwfApp.Start()

	return nil
}

func initLogFile(logNfPath []string) (string, error) {
	logTlsKeyPath := ""

	for _, path := range logNfPath {
		if err := logger_util.LogFileHook(logger.Log, path); err != nil {
			return "", err
		}

		if logTlsKeyPath != "" {
			continue
		}

		nfDir, _ := filepath.Split(path)
		tmpDir := filepath.Join(nfDir, "key")
		if err := os.MkdirAll(tmpDir, 0o775); err != nil {
			logger.InitLog.Errorf("Make directory %s failed: %+v", tmpDir, err)
			return "", err
		}
		_, name := filepath.Split(factory.N3iwfDefaultTLSKeyLogPath)
		logTlsKeyPath = filepath.Join(tmpDir, name)
	}

	return logTlsKeyPath, nil
}

func startSnapshot(n3iwfApp *service.N3iwfApp) {
	logger.MainLog.Infof("INIT SNAPSHOT Logger")

	for {
		//ADD KPM LOGGER VERSION and Config N3IWF
		n3iwfContext := snapshot.MakeN3IWFContextSnapshotFull(n3iwfApp.Context())
		logger.LogKPM_N3IWF_CONTEXT(map[string]any{
			"config":   n3iwfApp.Config(),
			"n3iwfctx": n3iwfContext,
		})

		time.Sleep(time.Second)
	}
}

func startKPMLogger() {
	logger.MainLog.Infof("INIT KPM Logger")
	for {
		storeData := snapshot.Agg.Snapshot()
		logger.LogKPMMetrics(storeData)
		time.Sleep(500 * time.Millisecond) // Sleep for 500 milliseconds
	}
	// This function will continuously log KPM metrics every 500 milliseconds.
}

func startRCLogger(app *service.N3iwfApp) {
	logger.MainLog.Infof("INIT RC Logger")
	metricsPath := os.Getenv("WIFI_METRICS_PATH")
	if metricsPath == "" {
		metricsPath = "/free5gc/wifi_metrics/metrics.json"
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		snap, err := rc.CollectWiFiMetricsSnapshot(metricsPath)
		if err != nil {
			logger.MainLog.Debugf("wifi metrics snapshot error: %v", err)
			continue
		}
		metrics := snapshot.Agg.Snapshot()
		var ueSnapshot *snapshot.N3iwfAppSnapshot
		if app != nil {
			ueSnapshot = snapshot.MakeN3IWFContextSnapshotFull(app.Context())
		}
		rc.EnrichSnapshot(&snap, metrics, ueSnapshot)
		snapshot.RCAgg.Update(snap)
		logger.LogRCMetrics(snapshot.RCAgg.Snapshot())
	}
}
