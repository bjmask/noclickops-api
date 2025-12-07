package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"net/http"
	"net/url"
	"os"

	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Config struct {
	DatabaseURL         string         `yaml:"database_url"`
	AdminDatabaseURL    string         `yaml:"admin_database_url"`
	JWTSecret           string         `yaml:"jwt_secret"`
	DeploymentType      string         `yaml:"deployment_type"` // "process" or "docker"
	ScannerImage        string         `yaml:"scanner_image"`
	MountADCFromHost    bool           `yaml:"mountApplicationDefaultCredentialsFromHost"`
	TrafficMonitorURL   string         `yaml:"traffic_monitor_url"`
	TrafficMonitorToken string         `yaml:"traffic_monitor_token"`
	Findings            FindingsConfig `yaml:"findings"`
}

type FindingsConfig struct {
	PollSeconds int            `yaml:"poll_seconds"`
	Baseline    BaselineConfig `yaml:"baseline"`
}

type BaselineConfig struct {
	PollSeconds    int `yaml:"poll_seconds"`
	LearnDays      int `yaml:"learn_days"`
	MinCount       int `yaml:"min_count"`
	MinSpanMinutes int `yaml:"min_span_minutes"`
}

type Tenant struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Name      string    `json:"name" gorm:"uniqueIndex"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Users     []User
	Scanners  []Scanner
}

type TrustedUser struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	TenantID  uint      `json:"tenant_id" gorm:"index"`
	Pattern   string    `json:"pattern" gorm:"size:256"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type TrustedRule struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	TenantID        uint      `json:"tenant_id" gorm:"index"`
	UserPattern     string    `json:"user_pattern" gorm:"size:256"`
	ResourcePattern string    `json:"resource_pattern" gorm:"size:256"`
	VerbPattern     string    `json:"verb_pattern" gorm:"size:256"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type User struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	TenantID     uint      `json:"tenant_id" gorm:"uniqueIndex:idx_tenant_email"`
	Email        string    `json:"email" gorm:"uniqueIndex:idx_tenant_email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Scanner struct {
	ID            uint            `json:"id" gorm:"primaryKey"`
	TenantID      uint            `json:"tenant_id" gorm:"uniqueIndex:idx_scanner_name_tenant"`
	Name          string          `json:"name" gorm:"uniqueIndex:idx_scanner_name_tenant"`
	CloudProvider string          `json:"cloud_provider"`
	ConfigJSON    json.RawMessage `json:"config_json" gorm:"type:jsonb"`
	Labels        json.RawMessage `json:"labels" gorm:"type:jsonb"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	DeletedAt     gorm.DeletedAt  `json:"-" gorm:"index"`
}

type app struct {
	db                *gorm.DB
	jwtSecret         []byte
	procs             map[uint]*exec.Cmd
	mu                sync.Mutex
	deploy            string
	kube              *kubernetes.Clientset
	image             string
	mountADC          bool
	trafficMonitorURL string
	trafficMonitorTok string
	portScanMu        sync.RWMutex
	portScans         []PortScanFinding
	portScanUpdated   time.Time
	portScanInterval  time.Duration
	baselineMu        sync.RWMutex
	baselines         map[BaselineKey]*BaselineEntry
	baselineUpdated   time.Time
	baselineInterval  time.Duration
	baselineLearn     time.Duration
	baselineMinCount  int
	baselineMinSpan   time.Duration
	policyCacheMu     sync.RWMutex
	policyCache       map[string]bool
}

func (a *app) addTrafficAuth(req *http.Request) {
	if strings.TrimSpace(a.trafficMonitorTok) != "" {
		req.Header.Set("Authorization", "Bearer "+a.trafficMonitorTok)
	}
}

type PortScanFinding struct {
	Source      string `json:"source"`
	UniquePorts int    `json:"unique_ports"`
}

type BaselineKey struct {
	SrcNS   string `json:"src_ns"`
	SrcApp  string `json:"src_app"`
	DstNS   string `json:"dst_ns"`
	DstApp  string `json:"dst_app"`
	DstPort int    `json:"dst_port"`
	Proto   int    `json:"proto"`
}

type BaselineEntry struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
	Baseline  bool      `json:"baseline"`
	PolicyHit bool      `json:"policy_hit"`
}

func main() {
	cfg := loadConfig()
	if cfg.Findings.PollSeconds == 0 {
		cfg.Findings.PollSeconds = 60
	}
	if cfg.Findings.Baseline.PollSeconds == 0 {
		cfg.Findings.Baseline.PollSeconds = cfg.Findings.PollSeconds
	}
	if cfg.Findings.Baseline.LearnDays == 0 {
		cfg.Findings.Baseline.LearnDays = 7
	}
	if cfg.Findings.Baseline.MinCount == 0 {
		cfg.Findings.Baseline.MinCount = 5
	}
	if cfg.Findings.Baseline.MinSpanMinutes == 0 {
		cfg.Findings.Baseline.MinSpanMinutes = 60
	}

	adminDSN := firstNonEmpty(os.Getenv("ADMIN_DATABASE_URL"), cfg.AdminDatabaseURL)
	targetDSN := firstNonEmpty(os.Getenv("DATABASE_URL"), cfg.DatabaseURL)
	jwtSecret := firstNonEmpty(os.Getenv("JWT_SECRET"), cfg.JWTSecret)
	scannerImage := firstNonEmpty(os.Getenv("SCANNER_IMAGE"), cfg.ScannerImage)
	trafficMonitorURL := firstNonEmpty(os.Getenv("TRAFFIC_MONITOR_URL"), cfg.TrafficMonitorURL)
	if trafficMonitorURL == "" {
		trafficMonitorURL = "http://127.0.0.1:8001/api/v1/namespaces/traffic-monitor/services/traffic-collector:8082/proxy/api/v1/findings"
	}
	trafficMonitorToken := firstNonEmpty(os.Getenv("TRAFFIC_MONITOR_TOKEN"), cfg.TrafficMonitorToken)
	if scannerImage == "" {
		scannerImage = "noclickops-scanner:latest2"
	}

	if targetDSN == "" {
		log.Fatal("DATABASE_URL is required (e.g. postgres://user:pass@host:5432/noclickops?sslmode=disable)")
	}
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	dbName, err := ensureDatabase(adminDSN, targetDSN)
	if err != nil {
		log.Fatalf("failed to ensure database %s: %v", dbName, err)
	}

	db, err := gorm.Open(postgres.Open(targetDSN), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	if err := db.AutoMigrate(&Tenant{}, &User{}, &Scanner{}, &TrustedUser{}, &TrustedRule{}); err != nil {
		log.Fatalf("migration failed: %v", err)
	}

	app := &app{
		db:                db,
		jwtSecret:         []byte(jwtSecret),
		procs:             make(map[uint]*exec.Cmd),
		deploy:            strings.ToLower(cfg.DeploymentType),
		image:             scannerImage,
		mountADC:          cfg.MountADCFromHost,
		trafficMonitorURL: trafficMonitorURL,
		trafficMonitorTok: trafficMonitorToken,
		portScanInterval:  time.Duration(cfg.Findings.PollSeconds) * time.Second,
		baselines:         make(map[BaselineKey]*BaselineEntry),
		baselineInterval:  time.Duration(cfg.Findings.Baseline.PollSeconds) * time.Second,
		baselineLearn:     time.Duration(cfg.Findings.Baseline.LearnDays*24) * time.Hour,
		baselineMinCount:  cfg.Findings.Baseline.MinCount,
		baselineMinSpan:   time.Duration(cfg.Findings.Baseline.MinSpanMinutes) * time.Minute,
		policyCache:       make(map[string]bool),
	}

	if app.deploy == "" {
		app.deploy = "process"
	}
	if app.deploy == "kubernetes" {
		kubeConfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		restCfg, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
		if err != nil {
			log.Fatalf("failed to load kubeconfig %s: %v", kubeConfig, err)
		}
		cs, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			log.Fatalf("failed to init kube client: %v", err)
		}
		app.kube = cs
		log.Printf("kubernetes deployment mode enabled")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := gin.Default()
	router.Use(gzip.Gzip(gzip.DefaultCompression))
	staticDir := resolveDir("web/static")
	router.Static("/static", staticDir)
	router.StaticFile("/", "web/index.html")
	router.StaticFile("/dashboard", "web/dashboard.html")
	router.StaticFile("/dashboard.html", "web/dashboard.html")
	router.StaticFile("/scanners", "web/scanners.html")
	router.StaticFile("/scanners.html", "web/scanners.html")
	router.StaticFile("/findings", "web/findings.html")
	router.StaticFile("/findings.html", "web/findings.html")
	router.StaticFile("/network", "web/network.html")
	router.StaticFile("/network.html", "web/network.html")
	router.StaticFile("/network_trusts", "web/network_trusts.html")
	router.StaticFile("/network_trusts.html", "web/network_trusts.html")
	router.StaticFile("/portscans", "web/portscans.html")
	router.StaticFile("/portscans.html", "web/portscans.html")
	router.StaticFile("/dns_exfil", "web/dns_exfil.html")
	router.StaticFile("/dns_exfil.html", "web/dns_exfil.html")
	router.StaticFile("/docs", "web/docs.html")
	router.StaticFile("/docs.html", "web/docs.html")
	router.StaticFile("/trusts", "web/trusts.html")
	router.StaticFile("/trusts.html", "web/trusts.html")
	router.StaticFile("/security", "web/security.html")
	router.StaticFile("/security.html", "web/security.html")
	router.StaticFile("/nav.html", "web/nav.html")
	router.StaticFile("/favicon.ico", "web/favicon.ico")
	docDir := resolveDir("docs")
	router.Static("/docs/assets", docDir)
	router.Static("/docs/md", docDir)
	// convenience redirect for logs UI -> use API endpoint
	router.GET("/scanners/:name/logs", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("/scanners/%s", url.PathEscape(c.Param("name"))))
	})
	router.GET("/scanners/:name", func(c *gin.Context) {
		c.File("web/scanner_detail.html")
	})
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := router.Group("/v1")
	v1.POST("/login", app.handleLogin)
	protected := v1.Group("/")
	protected.Use(app.authMiddleware())
	protected.POST("/tenants", app.handleCreateTenant)
	protected.GET("/scanners", app.handleScannersGet)
	protected.POST("/scanners", app.handleScannersPost)
	protected.GET("/scanners/:name", app.handleScannerGet)
	protected.PUT("/scanners/:name", app.handleScannerPut)
	protected.DELETE("/scanners/:name", app.handleScannerDelete)
	protected.GET("/me", app.handleMe)
	protected.GET("/scanners/health", app.handleAllScannersHealth)
	protected.GET("/scanners/:name/health", app.handleScannerHealth)
	protected.GET("/scanners/:name/logs", app.handleScannerLogs)
	protected.GET("/scanners/:name/findings", app.handleScannerFindings)
	protected.GET("/scanners/:name/map", app.handleScannerMap)
	// backward compatibility
	protected.GET("/scanners/:name/kube-map", app.handleScannerMap)
	protected.GET("/trusts", app.handleTrustsList)
	protected.POST("/trusts", app.handleTrustsCreate)
	protected.PUT("/trusts/:id", app.handleTrustsUpdate)
	protected.DELETE("/trusts/:id", app.handleTrustsDelete)

	protected.GET("/network/findings", app.handleNetworkFindings)
	protected.GET("/network/schema", app.handleNetworkSchema)
	protected.GET("/network/keys", app.handleNetworkKeys)
	protected.GET("/network/trusts", app.handleNetworkTrusts)
	protected.GET("/network/portscans", app.handlePortScans)
	protected.GET("/network/baseline", app.handleBaseline)
	protected.GET("/network/dns", app.handleDNSQueries)

	protected.GET("/security/shells", app.handleShellExecutions)

	addr := ":8080"
	log.Printf("API listening on %s", addr)
	if app.deploy == "kubernetes" {
		go func() {

			// Initial reconciliation
			if err := app.ensureAllDeployments(); err != nil {
				log.Printf("error ensuring deployments: %v", err)
			}
			// Periodic reconciliation loop
			ticker := time.NewTicker(1 * time.Minute)
			for range ticker.C {
				if err := app.ensureAllDeployments(); err != nil {
					log.Printf("error in reconciliation loop: %v", err)
				}
			}
		}()
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR to allow binding to an address in TIME_WAIT state.
				// This is useful for frequent restarts during development (air).
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return opErr
		},
	}

	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	if app.trafficMonitorURL != "" && app.portScanInterval > 0 {
		go app.startPortScanWatcher(ctx)
	}
	if app.trafficMonitorURL != "" && app.baselineInterval > 0 {
		go app.startBaselineWatcher(ctx)
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be caught, so don't need to add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// The context is used to inform the server it has 2 seconds to finish
	// the request it is currently handling
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
	}

	log.Println("Server exiting")
}

func loadConfig() Config {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "config.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("warning: failed to parse %s: %v", path, err)
	}
	if cfg.DeploymentType == "" {
		cfg.DeploymentType = "process"
	}
	return cfg
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func resolveDir(name string) string {
	cwd, _ := os.Getwd()
	candidates := []string{
		filepath.Join(cwd, name),
		filepath.Join(cwd, "noclickops-api", name),
		name,
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return name
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// ensureDatabase connects to adminDSN (or derives one from target) and creates the target DB if missing.
func ensureDatabase(adminDSN, targetDSN string) (string, error) {
	dbName, admin, err := deriveAdminDSN(adminDSN, targetDSN)
	if err != nil {
		return "", err
	}

	adminDB, err := gorm.Open(postgres.Open(admin), &gorm.Config{})
	if err != nil {
		return dbName, fmt.Errorf("admin connect failed: %w", err)
	}
	var exists bool
	row := adminDB.Raw("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = ?)", dbName).Row()
	if scanErr := row.Scan(&exists); scanErr != nil {
		return dbName, fmt.Errorf("check database existence: %w", scanErr)
	}
	if !exists {
		if err := adminDB.Exec("CREATE DATABASE " + dbName).Error; err != nil {
			return dbName, fmt.Errorf("create database: %w", err)
		}
		log.Printf("created database %s", dbName)
	}
	return dbName, nil
}

func deriveAdminDSN(adminDSN, targetDSN string) (string, string, error) {
	target, err := url.Parse(targetDSN)
	if err != nil {
		return "", "", fmt.Errorf("invalid DATABASE_URL: %w", err)
	}
	dbName := strings.TrimPrefix(target.Path, "/")
	if dbName == "" {
		return "", "", fmt.Errorf("DATABASE_URL missing db name")
	}
	if adminDSN != "" {
		return dbName, adminDSN, nil
	}
	// Derive admin connection pointing to postgres while keeping host/user/sslmode.
	admin := *target
	admin.Path = "/postgres"
	return dbName, admin.String(), nil
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

func (a *app) handleLogin(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	var user User
	if err := a.db.WithContext(c.Request.Context()).Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := a.buildToken(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	c.JSON(http.StatusOK, loginResponse{Token: token})
}

func (a *app) buildToken(user *User) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   user.ID,
		"tenant_id": user.TenantID,
		"email":     user.Email,
		"exp":       time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

type createTenantRequest struct {
	Name string `json:"name"`
}

func (a *app) handleCreateTenant(c *gin.Context) {
	var req createTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	t := Tenant{Name: strings.TrimSpace(req.Name)}
	if err := a.db.WithContext(c.Request.Context()).Create(&t).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, t)
}

type createScannerRequest struct {
	Name           string          `json:"name"`
	CloudProvider  string          `json:"cloud_provider"`
	Config         json.RawMessage `json:"config"`
	Labels         json.RawMessage `json:"labels,omitempty"`
	AWSAccessKey   string          `json:"aws_access_key_id,omitempty"`
	AWSSecretKey   string          `json:"aws_secret_access_key,omitempty"`
	AWSSession     string          `json:"aws_session_token,omitempty"`
	JiraToken      string          `json:"jira_token,omitempty"`
	JiraEmail      string          `json:"jira_email,omitempty"`
	GCPCredentials string          `json:"gcp_credentials_json,omitempty"`
}

func (a *app) handleScannersGet(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	var scanners []Scanner
	if err := a.db.WithContext(c.Request.Context()).Where("tenant_id = ?", principal.TenantID).Find(&scanners).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch scanners"})
		return
	}
	c.JSON(http.StatusOK, scanners)
}

func (a *app) handleScannersPost(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	var req createScannerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	provider := strings.ToLower(req.CloudProvider)
	if provider != "aws" && provider != "gcp" && provider != "azure" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cloud_provider must be one of aws,gcp,azure"})
		return
	}
	scanner := Scanner{
		TenantID:      principal.TenantID,
		Name:          req.Name,
		CloudProvider: provider,
		ConfigJSON:    req.Config,
		Labels:        req.Labels,
	}
	if err := a.db.WithContext(c.Request.Context()).Create(&scanner).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if a.deploy == "kubernetes" {
		if err := a.ensureKubeDeployment(c.Request.Context(), principal.TenantID, &scanner, &req); err != nil {
			log.Printf("failed to ensure deployment: %v", err)
		}
	} else {
		if err := a.spawnScannerProcess(c.Request.Context(), principal.TenantID, &scanner); err != nil {
			log.Printf("failed to start scanner process: %v", err)
		}
	}
	c.JSON(http.StatusCreated, scanner)
}

func (a *app) handleScannerGet(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	name := c.Param("name")
	var scanner Scanner
	if err := a.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND name = ?", principal.TenantID, name).
		First(&scanner).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scanner not found"})
		return
	}
	c.JSON(http.StatusOK, scanner)
}

func (a *app) handleScannerPut(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	name := c.Param("name")
	var scanner Scanner
	if err := a.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND name = ?", principal.TenantID, name).
		First(&scanner).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scanner not found"})
		return
	}
	var req createScannerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	provider := strings.ToLower(firstNonEmpty(req.CloudProvider, scanner.CloudProvider))
	if provider != "aws" && provider != "gcp" && provider != "azure" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cloud_provider must be one of aws,gcp,azure"})
		return
	}

	updates := map[string]interface{}{
		"cloud_provider": provider,
	}
	if len(req.Config) > 0 {
		updates["config_json"] = req.Config
	}
	if len(req.Labels) > 0 {
		updates["labels"] = req.Labels
	}

	if err := a.db.WithContext(c.Request.Context()).
		Model(&scanner).
		Updates(updates).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Reload latest config
	_ = a.db.First(&scanner, scanner.ID)

	if a.deploy == "kubernetes" {
		if err := a.ensureKubeDeployment(c.Request.Context(), principal.TenantID, &scanner, &req); err != nil {
			log.Printf("failed to ensure deployment: %v", err)
		}
	} else {
		if err := a.spawnScannerProcess(c.Request.Context(), principal.TenantID, &scanner); err != nil {
			log.Printf("failed to start scanner process: %v", err)
		}
	}
	c.JSON(http.StatusOK, scanner)
}

func (a *app) handleScannerDelete(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	name := c.Param("name")
	var scanner Scanner
	if err := a.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND name = ?", principal.TenantID, name).
		First(&scanner).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scanner not found"})
		return
	}
	var tenant Tenant
	if err := a.db.WithContext(c.Request.Context()).First(&tenant, principal.TenantID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	names := namesForScanner(scanner.Name)

	// Delete DB record
	if err := a.db.WithContext(c.Request.Context()).Delete(&scanner).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete scanner"})
		return
	}

	// Cleanup k8s resources if enabled
	if a.deploy == "kubernetes" && a.kube != nil {
		ns := namespaceFor(tenant.Name)
		go func() {
			grace := int64(0)
			_ = a.kube.AppsV1().Deployments(ns).Delete(context.Background(), names.deploy, metav1.DeleteOptions{GracePeriodSeconds: &grace})
			_ = a.kube.CoreV1().ConfigMaps(ns).Delete(context.Background(), names.cm, metav1.DeleteOptions{})
			_ = a.kube.CoreV1().Secrets(ns).Delete(context.Background(), names.secret, metav1.DeleteOptions{})
			_ = a.kube.CoreV1().Services(ns).Delete(context.Background(), names.svc, metav1.DeleteOptions{})
			_ = a.kube.NetworkingV1().NetworkPolicies(ns).Delete(context.Background(), names.np, metav1.DeleteOptions{})
			_ = a.kube.CoreV1().ServiceAccounts(ns).Delete(context.Background(), names.sa, metav1.DeleteOptions{})
			log.Printf("deleted k8s resources for scanner %s in namespace %s", scanner.Name, ns)
		}()
	} else {
		// stop local process if tracked
		a.mu.Lock()
		if cmd, ok := a.procs[scanner.ID]; ok {
			_ = cmd.Process.Kill()
			delete(a.procs, scanner.ID)
		}
		a.mu.Unlock()
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (a *app) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := c.GetHeader("Authorization")
		if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			c.Abort()
			return
		}
		tokenStr := strings.TrimSpace(authz[7:])
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return a.jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}
		userID, ok := claims["user_id"].(float64)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			c.Abort()
			return
		}
		var user User
		if err := a.db.WithContext(c.Request.Context()).First(&user, uint(userID)).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			c.Abort()
			return
		}
		c.Set("principal", &user)
		c.Next()
	}
}

func (a *app) spawnScannerProcess(ctx context.Context, tenantID uint, scanner *Scanner) error {
	if a.deploy != "process" {
		return nil
	}
	var tenant Tenant
	if err := a.db.WithContext(ctx).First(&tenant, tenantID).Error; err != nil {
		return fmt.Errorf("load tenant: %w", err)
	}
	baseDir := firstNonEmpty(os.Getenv("SCANNER_BASE_DIR"), "/tmp/noclickops")
	dir := filepath.Join(baseDir, fmt.Sprintf("noclickops-%s-%s", sanitize(tenant.Name), sanitize(scanner.Name)))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")

	// Convert stored JSON config to YAML for the Rust binary.
	var cfg interface{}
	if len(scanner.ConfigJSON) > 0 {
		if err := json.Unmarshal(scanner.ConfigJSON, &cfg); err != nil {
			return fmt.Errorf("decode scanner config: %w", err)
		}
	}
	yml, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	if err := os.WriteFile(cfgPath, yml, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	bin := firstNonEmpty(os.Getenv("SCANNER_BIN"), "../noclickops-scanner/target/debug/noclickops")
	cmd := exec.CommandContext(context.Background(), bin, "--config", cfgPath)
	logPath := filepath.Join(dir, "scanner.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start scanner: %w", err)
	}

	a.mu.Lock()
	a.procs[scanner.ID] = cmd
	a.mu.Unlock()
	log.Printf("started scanner %s (pid %d) with config %s", scanner.Name, cmd.Process.Pid, cfgPath)
	return nil
}

func sanitize(in string) string {
	return sanitizeLimited(in, 63)
}

func sanitizeLimited(in string, maxLen int) string {
	s := strings.ToLower(in)
	re := regexp.MustCompile(`[^a-z0-9.-]+`)
	s = re.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-.")
	if len(s) > maxLen {
		s = s[:maxLen]
		s = strings.Trim(s, "-.")
	}
	if s == "" {
		return "noclickops"
	}
	return s
}

func k8sName(prefix, name string) string {
	if strings.TrimSpace(name) == "" {
		return sanitizeLimited(prefix, 63)
	}
	return sanitizeLimited(fmt.Sprintf("%s-%s", prefix, name), 63)
}

type meResponse struct {
	Email      string `json:"email"`
	TenantID   uint   `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
}

func (a *app) handleMe(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	var tenant Tenant
	if err := a.db.WithContext(c.Request.Context()).First(&tenant, principal.TenantID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	c.JSON(http.StatusOK, meResponse{
		Email:      principal.Email,
		TenantID:   principal.TenantID,
		TenantName: tenant.Name,
	})
}

func (a *app) handleScannerHealth(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	name := c.Param("name")
	var scanner Scanner
	if err := a.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND name = ?", principal.TenantID, name).
		First(&scanner).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scanner not found"})
		return
	}
	names := namesForScanner(scanner.Name)
	var tenant Tenant
	if err := a.db.WithContext(c.Request.Context()).First(&tenant, principal.TenantID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}

	if a.deploy == "kubernetes" {
		ns := namespaceFor(tenant.Name)
		// Check deployment status
		if a.kube == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "kube client not initialized"})
			return
		}
		dep, err := a.kube.AppsV1().Deployments(ns).Get(c.Request.Context(), names.deploy, metav1.GetOptions{})
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"status": "not_found", "error": err.Error()})
			return
		}
		ready := dep.Status.ReadyReplicas
		c.JSON(http.StatusOK, gin.H{
			"name":   scanner.Name,
			"status": ifThen(ready > 0, "running", "pending"),
			"ready":  ready,
		})
		return
	}

	status := "not_started"
	pid := 0
	a.mu.Lock()
	cmd := a.procs[scanner.ID]
	a.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		pid = cmd.Process.Pid
		running := cmd.ProcessState == nil || !cmd.ProcessState.Exited()
		if running {
			if err := cmd.Process.Signal(syscall.Signal(0)); err == nil {
				status = "running"
			} else {
				status = "stopped"
			}
		} else {
			status = "stopped"
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"name":    scanner.Name,
		"status":  status,
		"pid":     pid,
		"config":  scanner.ConfigJSON,
		"started": status == "running",
	})
}

type ScannerHealthStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Ready   int32  `json:"ready,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Started bool   `json:"started"`
	Error   string `json:"error,omitempty"`
}

func (a *app) handleAllScannersHealth(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	var scanners []Scanner
	if err := a.db.WithContext(c.Request.Context()).Where("tenant_id = ?", principal.TenantID).Find(&scanners).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch scanners"})
		return
	}

	var tenant Tenant
	if err := a.db.WithContext(c.Request.Context()).First(&tenant, principal.TenantID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}

	// Fetch health for all scanners
	results := make([]ScannerHealthStatus, len(scanners))
	var wg sync.WaitGroup

	for i, scanner := range scanners {
		wg.Add(1)
		go func(idx int, sc Scanner) {
			defer wg.Done()
			health := a.getScannerHealthStatus(c.Request.Context(), &sc, &tenant)
			results[idx] = health
		}(i, scanner)
	}

	wg.Wait()
	c.JSON(http.StatusOK, gin.H{"scanners": results})
}

func (a *app) getScannerHealthStatus(ctx context.Context, scanner *Scanner, tenant *Tenant) ScannerHealthStatus {
	result := ScannerHealthStatus{
		Name:    scanner.Name,
		Status:  "unknown",
		Started: false,
	}

	names := namesForScanner(scanner.Name)

	if a.deploy == "kubernetes" {
		ns := namespaceFor(tenant.Name)
		if a.kube == nil {
			result.Status = "error"
			result.Error = "kube client not initialized"
			return result
		}

		dep, err := a.kube.AppsV1().Deployments(ns).Get(ctx, names.deploy, metav1.GetOptions{})
		if err != nil {
			result.Status = "not_found"
			result.Error = err.Error()
			return result
		}

		ready := dep.Status.ReadyReplicas
		result.Ready = ready
		if ready > 0 {
			result.Status = "running"
			result.Started = true
		} else {
			result.Status = "pending"
		}
		return result
	}

	// Process mode
	result.Status = "not_started"
	a.mu.Lock()
	cmd := a.procs[scanner.ID]
	a.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		result.PID = cmd.Process.Pid
		running := cmd.ProcessState == nil || !cmd.ProcessState.Exited()
		if running {
			if err := cmd.Process.Signal(syscall.Signal(0)); err == nil {
				result.Status = "running"
				result.Started = true
			} else {
				result.Status = "stopped"
			}
		} else {
			result.Status = "stopped"
		}
	}

	return result
}

func (a *app) handleScannerLogs(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	name := c.Param("name")
	var scanner Scanner
	if err := a.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND name = ?", principal.TenantID, name).
		First(&scanner).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scanner not found"})
		return
	}
	var tenant Tenant
	if err := a.db.WithContext(c.Request.Context()).First(&tenant, principal.TenantID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	if a.deploy != "kubernetes" || a.kube == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "logs available only in kubernetes mode"})
		return
	}
	ns := namespaceFor(tenant.Name)
	pods, err := a.kube.CoreV1().Pods(ns).List(c.Request.Context(), metav1.ListOptions{
		LabelSelector: "app=noclickops-scanner,scanner=" + sanitize(scanner.Name),
	})
	if err != nil || len(pods.Items) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "pod not found"})
		return
	}
	podName := pods.Items[0].Name
	tail := int64(200)
	req := a.kube.CoreV1().Pods(ns).GetLogs(podName, &corev1.PodLogOptions{
		Container: "scanner",
		Follow:    true,
		TailLines: &tail,
	})
	stream, err := req.Stream(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer stream.Close()
	w := c.Writer
	w.Header().Set("Content-Type", "text/plain")
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 4096)
	for {
		n, readErr := stream.Read(buf)
		if n > 0 {
			if _, _ = w.Write(buf[:n]); flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				log.Printf("log stream error: %v", readErr)
			}
			break
		}
	}
}

func (a *app) handleScannerFindings(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	name := c.Param("name")
	var scanner Scanner
	if err := a.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND name = ?", principal.TenantID, name).
		First(&scanner).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scanner not found"})
		return
	}
	var tenant Tenant
	if err := a.db.WithContext(c.Request.Context()).First(&tenant, principal.TenantID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	if a.deploy != "kubernetes" || a.kube == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "findings available only in kubernetes mode"})
		return
	}
	ns := namespaceFor(tenant.Name)
	pods, err := a.kube.CoreV1().Pods(ns).List(c.Request.Context(), metav1.ListOptions{
		LabelSelector: "app=noclickops-scanner,scanner=" + sanitize(scanner.Name),
	})
	if err != nil || len(pods.Items) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "pod not found"})
		return
	}
	podName := pods.Items[0].Name
	raw := a.kube.CoreV1().RESTClient().
		Get().
		Namespace(ns).
		Resource("pods").
		Name(podName + ":8081").
		SubResource("proxy").
		Suffix("api/v1/findings").
		Do(c.Request.Context())
	bytes, err := raw.Raw()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Filter findings based on blacklist to ensure UI doesn't show ignored events
	// even if the scanner hasn't been restarted or has old findings in memory.
	var findings []map[string]interface{}
	if err := json.Unmarshal(bytes, &findings); err != nil {
		// If parsing fails, just return raw bytes (fallback)
		c.Data(http.StatusOK, "application/json", bytes)
		return
	}

	// Parse config to get blacklist
	var cfgMap map[string]interface{}
	if len(scanner.ConfigJSON) > 0 {
		_ = json.Unmarshal(scanner.ConfigJSON, &cfgMap)
	}
	if cfgMap == nil {
		cfgMap = make(map[string]interface{})
	}

	// Get blacklist from config + defaults
	blacklist := []string{
		"AssumeRole",
		"*AssumeRole*",
		"Decrypt",
		"Encrypt",
		"GetCallerIdentity",
		"BatchGetImage",
		"FilterLogEvents",
		"UpdateInstanceInformation",
		"GenerateDataKey",
		"CreateLogStream",
	}
	if bl, ok := cfgMap["blacklist_events"].([]interface{}); ok {
		for _, v := range bl {
			if s, ok := v.(string); ok {
				blacklist = append(blacklist, s)
			}
		}
	}

	// Helper to check if string matches any blacklist pattern (glob or contains)
	isBlacklisted := func(verb string) bool {
		verbLower := strings.ToLower(verb)
		for _, pattern := range blacklist {
			patLower := strings.ToLower(pattern)
			// Simple check: wildcard or substring
			if strings.Contains(patLower, "*") || strings.Contains(patLower, "?") {
				// Convert simple glob to regex: . -> \., * -> .*, ? -> .
				// This is a rough approximation of the Rust glob logic
				reStr := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(patLower), "\\*", ".*"), "\\?", ".") + "$"
				if matched, _ := regexp.MatchString(reStr, verbLower); matched {
					return true
				}
			} else if strings.Contains(verbLower, patLower) {
				return true
			}
		}
		return false
	}

	var filtered []map[string]interface{}
	for _, f := range findings {
		verb, _ := f["verb"].(string)
		if verb != "" && isBlacklisted(verb) {
			continue
		}
		filtered = append(filtered, f)
	}

	c.JSON(http.StatusOK, filtered)
}

func (a *app) handleScannerMap(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	name := c.Param("name")
	var scanner Scanner
	if err := a.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND name = ?", principal.TenantID, name).
		First(&scanner).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scanner not found"})
		return
	}
	var tenant Tenant
	if err := a.db.WithContext(c.Request.Context()).First(&tenant, principal.TenantID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	if a.deploy == "kubernetes" && a.kube != nil {
		ns := namespaceFor(tenant.Name)
		pods, err := a.kube.CoreV1().Pods(ns).List(c.Request.Context(), metav1.ListOptions{
			LabelSelector: "app=noclickops-scanner,scanner=" + sanitize(scanner.Name),
		})
		if err != nil || len(pods.Items) == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "pod not found"})
			return
		}
		podName := pods.Items[0].Name
		raw := a.kube.CoreV1().RESTClient().
			Get().
			Namespace(ns).
			Resource("pods").
			Name(podName + ":8081").
			SubResource("proxy").
			Suffix("api/v1/map").
			Do(c.Request.Context())
		bytes, err := raw.Raw()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		filtered := a.applyTrustedUserFilter(c.Request.Context(), tenant.ID, bytes)
		c.Data(http.StatusOK, "application/json", filtered)
		return
	}

	// process/development mode: attempt local HTTP fetch from scanner port
	resp, err := http.Get("http://127.0.0.1:8081/api/v1/map")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "map unavailable (process mode): " + err.Error()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	filtered := a.applyTrustedUserFilter(c.Request.Context(), tenant.ID, body)
	c.Data(resp.StatusCode, "application/json", filtered)
}

func (a *app) applyTrustedUserFilter(ctx context.Context, tenantID uint, body []byte) []byte {
	// Previously we filtered trusted entries from the map response.
	// Now we keep all entries and rely on the UI to annotate trust matches.
	return body
}

func compilePatterns(patterns []string) []*regexp.Regexp {
	var res []*regexp.Regexp
	for _, pat := range patterns {
		p := strings.TrimSpace(pat)
		if p == "" {
			continue
		}
		var re *regexp.Regexp
		if strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") && len(p) > 2 {
			inner := p[1 : len(p)-1]
			r, err := regexp.Compile("(?i)" + inner)
			if err != nil {
				continue
			}
			re = r
		} else {
			escaped := regexp.QuoteMeta(p)
			escaped = strings.ReplaceAll(escaped, "\\*", ".*")
			escaped = strings.ReplaceAll(escaped, "\\?", ".")
			r, err := regexp.Compile("(?i)^" + escaped + "$")
			if err != nil {
				continue
			}
			re = r
		}
		res = append(res, re)
	}
	return res
}

func matchesAny(val string, regexes []*regexp.Regexp) bool {
	for _, r := range regexes {
		if r.MatchString(val) {
			return true
		}
	}
	return false
}

type trustRuleCompiled struct {
	user     *regexp.Regexp
	resource *regexp.Regexp
	verb     *regexp.Regexp
}

func (a *app) trustedRules(ctx context.Context, tenantID uint) ([]trustRuleCompiled, error) {
	var list []TrustedRule
	if err := a.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&list).Error; err != nil {
		return nil, err
	}
	var compiled []trustRuleCompiled
	for _, r := range list {
		ur := compilePatterns([]string{fallbackWildcard(r.UserPattern)})
		rr := compilePatterns([]string{fallbackWildcard(r.ResourcePattern)})
		vr := compilePatterns([]string{fallbackWildcard(r.VerbPattern)})
		if len(ur) == 0 || len(rr) == 0 || len(vr) == 0 {
			continue
		}
		compiled = append(compiled, trustRuleCompiled{
			user:     ur[0],
			resource: rr[0],
			verb:     vr[0],
		})
	}
	return compiled, nil
}

func fallbackWildcard(s string) string {
	v := strings.TrimSpace(s)
	if v == "" || strings.EqualFold(v, "all") {
		return "*"
	}
	return v
}

func ruleMatches(rules []trustRuleCompiled, user, resource, verb string) bool {
	for _, r := range rules {
		if r.user.MatchString(user) && r.resource.MatchString(resource) && r.verb.MatchString(verb) {
			return true
		}
	}
	return false
}

func (a *app) handleTrustsList(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	var list []TrustedRule
	if err := a.db.WithContext(c.Request.Context()).
		Where("tenant_id = ?", principal.TenantID).
		Order("id asc").
		Find(&list).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (a *app) handleTrustsCreate(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	var req struct {
		UserPattern     string `json:"user_pattern"`
		ResourcePattern string `json:"resource_pattern"`
		VerbPattern     string `json:"verb_pattern"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	req.UserPattern = strings.TrimSpace(req.UserPattern)
	req.ResourcePattern = strings.TrimSpace(req.ResourcePattern)
	req.VerbPattern = strings.TrimSpace(req.VerbPattern)
	if req.UserPattern == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_pattern is required"})
		return
	}
	if req.ResourcePattern == "" {
		req.ResourcePattern = "*"
	}
	if req.VerbPattern == "" {
		req.VerbPattern = "*"
	}
	tr := TrustedRule{
		TenantID:        principal.TenantID,
		UserPattern:     req.UserPattern,
		ResourcePattern: req.ResourcePattern,
		VerbPattern:     req.VerbPattern,
	}
	if err := a.db.WithContext(c.Request.Context()).Create(&tr).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, tr)
}

func (a *app) handleTrustsUpdate(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var tr TrustedRule
	if err := a.db.WithContext(c.Request.Context()).
		Where("id = ? AND tenant_id = ?", id, principal.TenantID).
		First(&tr).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var req struct {
		UserPattern     string `json:"user_pattern"`
		ResourcePattern string `json:"resource_pattern"`
		VerbPattern     string `json:"verb_pattern"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if strings.TrimSpace(req.UserPattern) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_pattern is required"})
		return
	}
	tr.UserPattern = strings.TrimSpace(req.UserPattern)
	tr.ResourcePattern = strings.TrimSpace(req.ResourcePattern)
	if tr.ResourcePattern == "" {
		tr.ResourcePattern = "*"
	}
	tr.VerbPattern = strings.TrimSpace(req.VerbPattern)
	if tr.VerbPattern == "" {
		tr.VerbPattern = "*"
	}
	if err := a.db.WithContext(c.Request.Context()).Save(&tr).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tr)
}

func (a *app) handleTrustsDelete(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var tr TrustedRule
	if err := a.db.WithContext(c.Request.Context()).
		Where("id = ? AND tenant_id = ?", id, principal.TenantID).
		First(&tr).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := a.db.WithContext(c.Request.Context()).Delete(&tr).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func namespaceFor(tenantName string) string {
	return sanitizeLimited(tenantName, 63)
}

type k8sNames struct {
	deploy string
	svc    string
	sa     string
	cm     string
	secret string
	np     string
}

func namesForScanner(scannerName string) k8sNames {
	base := k8sName("scanner", scannerName)
	return k8sNames{
		deploy: base,
		svc:    k8sName(base, "svc"),
		sa:     k8sName(base, "sa"),
		cm:     k8sName(base, "config"),
		secret: k8sName(base, "secret"),
		np:     k8sName(base, "np"),
	}
}

func (a *app) handleNetworkFindings(c *gin.Context) {
	if a.trafficMonitorURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "traffic monitor URL not configured"})
		return
	}
	targetURL := a.trafficMonitorURL
	raw := c.Request.URL.RawQuery
	if raw != "" {
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		targetURL = targetURL + sep + raw
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, targetURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.addTrafficAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.JSON(resp.StatusCode, gin.H{"error": string(body)})
		return
	}
	c.Data(http.StatusOK, "application/json", body)
}

func (a *app) handleNetworkSchema(c *gin.Context) {
	if a.trafficMonitorURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "traffic monitor URL not configured"})
		return
	}
	// derive schema endpoint from findings URL
	schemaURL := strings.Replace(a.trafficMonitorURL, "/findings", "/schemas", 1)
	raw := c.Request.URL.RawQuery
	if raw != "" {
		sep := "?"
		if strings.Contains(schemaURL, "?") {
			sep = "&"
		}
		schemaURL = schemaURL + sep + raw
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, schemaURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.addTrafficAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.JSON(resp.StatusCode, gin.H{"error": string(body)})
		return
	}
	c.Data(http.StatusOK, "application/json", body)
}

func (a *app) handleNetworkTrusts(c *gin.Context) {
	if a.trafficMonitorURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "traffic monitor URL not configured"})
		return
	}
	// Build query params, defaulting to collapse=none and hide_src_port=true for matching.
	qs := c.Request.URL.Query()
	if qs.Get("collapse") == "" {
		qs.Set("collapse", "none")
	}
	if qs.Get("hide_src_port") == "" {
		qs.Set("hide_src_port", "true")
	}
	if qs.Get("per_page") == "" {
		qs.Set("per_page", "500")
	}
	if qs.Get("page") == "" {
		qs.Set("page", "1")
	}

	type trustEdge struct {
		Src       string `json:"src"`
		Dst       string `json:"dst"`
		Namespace string `json:"namespace"`
		Direction string `json:"direction"`
		Policy    string `json:"policy"`
		Ports     []int  `json:"ports"`
	}
	type finding struct {
		A       string `json:"a"`
		B       string `json:"b"`
		Proto   int    `json:"proto"`
		APort   *int   `json:"a_port"`
		BPort   *int   `json:"b_port"`
		Packets int64  `json:"packets_ab"`
	}
	// Fetch trusts
	trustURL := strings.Replace(a.trafficMonitorURL, "/findings", "/trusts", 1) + "?" + qs.Encode()
	trustReq, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, trustURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.addTrafficAuth(trustReq)
	trustResp, err := http.DefaultClient.Do(trustReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer trustResp.Body.Close()
	trustBody, err := io.ReadAll(trustResp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if trustResp.StatusCode < 200 || trustResp.StatusCode >= 300 {
		c.JSON(trustResp.StatusCode, gin.H{"error": string(trustBody)})
		return
	}
	var trusts []trustEdge
	if err := json.Unmarshal(trustBody, &trusts); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "decode trusts: " + err.Error()})
		return
	}

	// Fetch findings with same filters
	findURL := a.trafficMonitorURL + "?" + qs.Encode()
	findReq, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, findURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.addTrafficAuth(findReq)
	findResp, err := http.DefaultClient.Do(findReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer findResp.Body.Close()
	findBody, err := io.ReadAll(findResp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if findResp.StatusCode < 200 || findResp.StatusCode >= 300 {
		c.JSON(findResp.StatusCode, gin.H{"error": string(findBody)})
		return
	}
	var findWrapper struct {
		Items []finding `json:"items"`
		Total int       `json:"total"`
	}
	if err := json.Unmarshal(findBody, &findWrapper); err != nil {
		// fallback to bare array
		if err := json.Unmarshal(findBody, &findWrapper.Items); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "decode findings: " + err.Error()})
			return
		}
	}

	// Build rows with trust match
	type row struct {
		Src     string `json:"src"`
		Dst     string `json:"dst"`
		Proto   int    `json:"proto"`
		DstPort int    `json:"dst_port"`
		Trusted bool   `json:"trusted"`
		Policy  string `json:"policy,omitempty"`
	}
	// Compute destination port from a_port and b_port using ephemeral port heuristics
	getDstPort := func(f finding) int {
		aPort := 0
		if f.APort != nil {
			aPort = *f.APort
		}
		bPort := 0
		if f.BPort != nil {
			bPort = *f.BPort
		}
		isEphemeral := func(p int) bool { return p >= 32768 }
		aEphem := isEphemeral(aPort)
		bEphem := isEphemeral(bPort)
		if aEphem && !bEphem {
			return bPort
		} else if bEphem && !aEphem {
			return aPort
		} else if !aEphem && !bEphem {
			if aPort != 0 {
				return aPort
			}
			return bPort
		} else {
			if aPort != 0 && bPort != 0 {
				if aPort < bPort {
					return aPort
				}
				return bPort
			} else if aPort != 0 {
				return aPort
			}
			return bPort
		}
	}

	match := func(f finding) (bool, string) {
		port := getDstPort(f)
		for _, t := range trusts {
			if t.Src == f.A && t.Dst == f.B {
				if len(t.Ports) == 0 {
					return true, t.Policy
				}
				for _, p := range t.Ports {
					if p == 0 || port == p {
						return true, t.Policy
					}
				}
			}
		}
		return false, ""
	}

	rows := make([]row, 0, len(findWrapper.Items))
	for _, f := range findWrapper.Items {
		ok, pol := match(f)
		port := getDstPort(f)
		rows = append(rows, row{
			Src:     f.A,
			Dst:     f.B,
			Proto:   f.Proto,
			DstPort: port,
			Trusted: ok,
			Policy:  pol,
		})
	}
	c.JSON(http.StatusOK, gin.H{"items": rows})
}

func (a *app) handleNetworkKeys(c *gin.Context) {
	if a.trafficMonitorURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "traffic monitor URL not configured"})
		return
	}
	keysURL := strings.Replace(a.trafficMonitorURL, "/findings", "/findings/keys", 1)
	raw := c.Request.URL.RawQuery
	if raw != "" {
		sep := "?"
		if strings.Contains(keysURL, "?") {
			sep = "&"
		}
		keysURL = keysURL + sep + raw
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, keysURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.addTrafficAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.JSON(resp.StatusCode, gin.H{"error": string(body)})
		return
	}
	c.Data(http.StatusOK, "application/json", body)
}

func (a *app) handlePortScans(c *gin.Context) {
	a.portScanMu.RLock()
	items := append([]PortScanFinding(nil), a.portScans...)
	updated := a.portScanUpdated
	a.portScanMu.RUnlock()
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"updated_at": updated,
		"interval_s": int(a.portScanInterval.Seconds()),
	})
}

func (a *app) handleBaseline(c *gin.Context) {
	a.baselineMu.RLock()
	items := make([]map[string]interface{}, 0, len(a.baselines))
	for k, v := range a.baselines {
		items = append(items, map[string]interface{}{
			"src_ns":     k.SrcNS,
			"src_app":    k.SrcApp,
			"dst_ns":     k.DstNS,
			"dst_app":    k.DstApp,
			"dst_port":   k.DstPort,
			"proto":      k.Proto,
			"first_seen": v.FirstSeen,
			"last_seen":  v.LastSeen,
			"count":      v.Count,
			"baseline":   v.Baseline,
			"policy_hit": v.PolicyHit,
		})
	}
	updated := a.baselineUpdated
	a.baselineMu.RUnlock()
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"updated_at": updated,
		"interval_s": int(a.baselineInterval.Seconds()),
	})
}

func (a *app) handleDNSQueries(c *gin.Context) {
	if a.trafficMonitorURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "traffic monitor URL not configured"})
		return
	}
	// Replace /findings with /network/dns in the base URL
	dnsURL := strings.Replace(a.trafficMonitorURL, "/findings", "/network/dns", 1)
	raw := c.Request.URL.RawQuery
	if raw != "" {
		sep := "?"
		if strings.Contains(dnsURL, "?") {
			sep = "&"
		}
		dnsURL = dnsURL + sep + raw
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, dnsURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.addTrafficAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.JSON(resp.StatusCode, gin.H{"error": string(body)})
		return
	}
	c.Data(http.StatusOK, "application/json", body)
}

func (a *app) handleShellExecutions(c *gin.Context) {
	if a.trafficMonitorURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "traffic monitor URL not configured"})
		return
	}
	// Replace /findings with /security/shells in the base URL
	shellsURL := strings.Replace(a.trafficMonitorURL, "/findings", "/security/shells", 1)
	raw := c.Request.URL.RawQuery
	if raw != "" {
		sep := "?"
		if strings.Contains(shellsURL, "?") {
			sep = "&"
		}
		shellsURL = shellsURL + sep + raw
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, shellsURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.addTrafficAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.JSON(resp.StatusCode, gin.H{"error": string(body)})
		return
	}
	c.Data(http.StatusOK, "application/json", body)
}

func (a *app) startPortScanWatcher(ctx context.Context) {
	if a.trafficMonitorURL == "" || a.portScanInterval <= 0 {
		return
	}
	ticker := time.NewTicker(a.portScanInterval)
	defer ticker.Stop()
	_ = a.refreshPortScans(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = a.refreshPortScans(ctx)
		}
	}
}

func (a *app) startBaselineWatcher(ctx context.Context) {
	if a.trafficMonitorURL == "" || a.baselineInterval <= 0 {
		return
	}
	ticker := time.NewTicker(a.baselineInterval)
	defer ticker.Stop()
	_ = a.refreshBaseline(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = a.refreshBaseline(ctx)
		}
	}
}

func (a *app) refreshPortScans(ctx context.Context) error {
	findings, err := a.fetchAllNetworkFindings(ctx)
	if err != nil {
		log.Printf("portscan refresh: %v", err)
		return err
	}
	type set map[int]struct{}
	portsBySrc := make(map[string]set)
	for _, f := range findings {
		src, _ := f["a"].(string)
		if src == "" {
			continue
		}
		// Compute destination port from a_port and b_port
		aPort := intFromAny(f["a_port"])
		bPort := intFromAny(f["b_port"])
		isEphemeral := func(p int) bool { return p >= 32768 }
		var port int
		aEphem := isEphemeral(aPort)
		bEphem := isEphemeral(bPort)
		if aEphem && !bEphem {
			port = bPort
		} else if bEphem && !aEphem {
			port = aPort
		} else if !aEphem && !bEphem {
			if aPort != 0 {
				port = aPort
			} else {
				port = bPort
			}
		} else {
			if aPort != 0 && bPort != 0 {
				if aPort < bPort {
					port = aPort
				} else {
					port = bPort
				}
			} else if aPort != 0 {
				port = aPort
			} else {
				port = bPort
			}
		}
		if port <= 0 {
			continue
		}
		if _, ok := portsBySrc[src]; !ok {
			portsBySrc[src] = make(set)
		}
		portsBySrc[src][port] = struct{}{}
	}
	var results []PortScanFinding
	for src, setPorts := range portsBySrc {
		if len(setPorts) <= 5 {
			continue
		}
		results = append(results, PortScanFinding{
			Source:      src,
			UniquePorts: len(setPorts),
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].UniquePorts == results[j].UniquePorts {
			return results[i].Source < results[j].Source
		}
		return results[i].UniquePorts > results[j].UniquePorts
	})
	a.portScanMu.Lock()
	a.portScans = results
	a.portScanUpdated = time.Now()
	a.portScanMu.Unlock()
	return nil
}

func (a *app) refreshBaseline(ctx context.Context) error {
	findings, err := a.fetchAllNetworkFindings(ctx)
	if err != nil {
		log.Printf("baseline refresh: %v", err)
		return err
	}
	baselineCut := time.Now().Add(-a.baselineLearn)
	minSpan := a.baselineMinSpan
	minCount := a.baselineMinCount

	tmp := make(map[BaselineKey]*BaselineEntry)

	for _, f := range findings {
		srcLabel, _ := f["a"].(string)
		dstLabel, _ := f["b"].(string)
		srcParsed := parseEndpointLabelGo(srcLabel)
		dstParsed := parseEndpointLabelGo(dstLabel)
		srcKind, srcName := kindNameFromString(fmt.Sprint(f["o_a"]))
		dstKind, dstName := kindNameFromString(fmt.Sprint(f["o_b"]))
		srcOwner := normalizeOwner(srcKind, srcName)
		dstOwner := normalizeOwner(dstKind, dstName)

		// Compute destination port from a_port and b_port
		aPort := intFromAny(f["a_port"])
		bPort := intFromAny(f["b_port"])
		isEphemeral := func(p int) bool { return p >= 32768 }
		var dstPort int
		aEphem := isEphemeral(aPort)
		bEphem := isEphemeral(bPort)
		if aEphem && !bEphem {
			dstPort = bPort
		} else if bEphem && !aEphem {
			dstPort = aPort
		} else if !aEphem && !bEphem {
			if aPort != 0 {
				dstPort = aPort
			} else {
				dstPort = bPort
			}
		} else {
			if aPort != 0 && bPort != 0 {
				if aPort < bPort {
					dstPort = aPort
				} else {
					dstPort = bPort
				}
			} else if aPort != 0 {
				dstPort = aPort
			} else {
				dstPort = bPort
			}
		}
		proto := intFromAny(f["proto"])

		key := BaselineKey{
			SrcNS:   srcParsed.Namespace,
			SrcApp:  srcOwner,
			DstNS:   dstParsed.Namespace,
			DstApp:  dstOwner,
			DstPort: dstPort,
			Proto:   proto,
		}
		entry, ok := tmp[key]
		if !ok {
			entry = &BaselineEntry{
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Count:     0,
				PolicyHit: a.policyExists(ctx, srcParsed.Namespace) || a.policyExists(ctx, dstParsed.Namespace),
			}
			tmp[key] = entry
		}
		entry.Count++
		entry.LastSeen = time.Now()
		if entry.FirstSeen.After(time.Now()) {
			entry.FirstSeen = time.Now()
		}
	}

	// Merge into shared map with promotion rules
	now := time.Now()
	a.baselineMu.Lock()
	if a.baselines == nil {
		a.baselines = make(map[BaselineKey]*BaselineEntry)
	}
	for k, newEntry := range tmp {
		existing, ok := a.baselines[k]
		if !ok {
			a.baselines[k] = newEntry
			continue
		}
		if newEntry.FirstSeen.Before(existing.FirstSeen) {
			existing.FirstSeen = newEntry.FirstSeen
		}
		if newEntry.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = newEntry.LastSeen
		}
		existing.Count += newEntry.Count
		existing.PolicyHit = existing.PolicyHit || newEntry.PolicyHit
	}
	for k, v := range a.baselines {
		span := v.LastSeen.Sub(v.FirstSeen)
		if !v.Baseline && v.FirstSeen.Before(baselineCut) && v.Count >= minCount && span >= minSpan {
			v.Baseline = true
		}
		// prune stale entries older than learn window * 2 without updates
		if now.Sub(v.LastSeen) > a.baselineLearn*2 {
			delete(a.baselines, k)
		}
	}
	a.baselineUpdated = now
	// make slice for logging or other uses
	a.baselineMu.Unlock()
	return nil
}

func (a *app) fetchAllNetworkFindings(ctx context.Context) ([]map[string]interface{}, error) {
	if a.trafficMonitorURL == "" {
		return nil, errors.New("traffic monitor URL not configured")
	}
	var all []map[string]interface{}
	page := 1
	perPage := 500
	for page <= 50 { // sane upper bound
		reqURL := a.trafficMonitorURL
		sep := "?"
		if strings.Contains(reqURL, "?") {
			sep = "&"
		}
		reqURL = fmt.Sprintf("%s%shide_src_port=true&collapse=none&page=%d&per_page=%d", reqURL, sep, page, perPage)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		a.addTrafficAuth(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("traffic monitor status %d: %s", resp.StatusCode, string(body))
		}
		var wrapper struct {
			Items []map[string]interface{} `json:"items"`
			Total int                      `json:"total"`
		}
		var pageItems []map[string]interface{}
		if err := json.Unmarshal(body, &wrapper); err == nil && len(wrapper.Items) > 0 {
			pageItems = wrapper.Items
		} else if err := json.Unmarshal(body, &pageItems); err != nil {
			return nil, fmt.Errorf("failed to decode findings: %w", err)
		}
		if len(pageItems) == 0 {
			break
		}
		all = append(all, pageItems...)
		total := wrapper.Total
		if total > 0 && len(all) >= total {
			break
		}
		if len(pageItems) < perPage {
			break
		}
		page++
	}
	return all, nil
}

type parsedEndpoint struct {
	Namespace string
	Pod       string
	Node      string
	Raw       string
}

func parseEndpointLabelGo(label string) parsedEndpoint {
	parts := strings.Split(label, ":")
	if len(parts) >= 3 && parts[0] == "pod" {
		return parsedEndpoint{Namespace: parts[1], Pod: parts[2], Raw: label}
	}
	if len(parts) >= 3 && parts[0] == "node" {
		return parsedEndpoint{Node: parts[2], Raw: label}
	}
	return parsedEndpoint{Raw: label}
}

func kindNameFromString(s string) (kind, name string) {
	if strings.HasPrefix(s, "o:") {
		s = strings.TrimPrefix(s, "o:")
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", s
}

func normalizeOwner(kind, name string) string {
	if kind == "" && name == "" {
		return ""
	}
	if kind == "rs" && name != "" {
		// Best-effort derive deployment name by trimming trailing hash
		base := name
		if idx := strings.LastIndex(name, "-"); idx > 0 {
			base = name[:idx]
		}
		return fmt.Sprintf("dep:%s", base)
	}
	if kind != "" {
		return fmt.Sprintf("%s:%s", kind, name)
	}
	return name
}

func intFromAny(v interface{}) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(t)
		return i
	default:
		return 0
	}
}

func (a *app) policyExists(ctx context.Context, ns string) bool {
	if ns == "" || a.kube == nil {
		return false
	}
	a.policyCacheMu.RLock()
	val, ok := a.policyCache[ns]
	a.policyCacheMu.RUnlock()
	if ok {
		return val
	}
	found := false
	if npList, err := a.kube.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{Limit: 1}); err == nil && len(npList.Items) > 0 {
		found = true
	}
	if !found {
		if cnpList, err := a.kube.RESTClient().Get().AbsPath("/apis/cilium.io/v2/namespaces/"+ns+"/ciliumnetworkpolicies").Param("limit", "1").DoRaw(ctx); err == nil && len(cnpList) > 0 {
			found = true
		}
	}
	a.policyCacheMu.Lock()
	a.policyCache[ns] = found
	a.policyCacheMu.Unlock()
	return found
}

func ifThen(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func hashMap(data map[string][]byte) string {
	if len(data) == 0 {
		return ""
	}
	h := sha256.New()
	for k, v := range data {
		h.Write([]byte(k))
		h.Write(v)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (a *app) ensureAllDeployments() error {
	if a.deploy != "kubernetes" || a.kube == nil {
		return nil
	}
	var scanners []Scanner
	if err := a.db.Find(&scanners).Error; err != nil {
		return err
	}
	log.Printf("ensuring deployments for %d scanners", len(scanners))
	for i := range scanners {
		log.Printf("ensuring deployment for scanner %s (tenant %d)", scanners[i].Name, scanners[i].TenantID)
		if err := a.ensureKubeDeployment(context.Background(), scanners[i].TenantID, &scanners[i], nil); err != nil {
			log.Printf("ensure deployment for %s failed: %v", scanners[i].Name, err)
		}
	}
	return nil
}

func (a *app) ensureKubeDeployment(ctx context.Context, tenantID uint, scanner *Scanner, req *createScannerRequest) error {
	if a.kube == nil {
		return fmt.Errorf("kube client not initialized")
	}
	var tenant Tenant
	if err := a.db.WithContext(ctx).First(&tenant, tenantID).Error; err != nil {
		return fmt.Errorf("load tenant: %w", err)
	}
	ns := namespaceFor(tenant.Name)
	names := namesForScanner(scanner.Name)
	log.Printf("reconciling scanner %s (tenant=%s id=%d) in namespace %s", scanner.Name, tenant.Name, tenant.ID, ns)
	labels := map[string]string{
		"app":     "noclickops-scanner",
		"scanner": sanitize(scanner.Name),
		"tenant":  fmt.Sprintf("%d", tenant.ID),
		"cloud":   scanner.CloudProvider,
	}
	if len(scanner.Labels) > 0 {
		var userLabels map[string]string
		if err := json.Unmarshal(scanner.Labels, &userLabels); err == nil {
			for k, v := range userLabels {
				labels[k] = v
			}
		}
	}

	// Namespace
	if _, err := a.kube.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err != nil {
		nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: labels}}
		if _, createErr := a.kube.CoreV1().Namespaces().Create(ctx, nsObj, metav1.CreateOptions{}); createErr != nil {
			log.Printf("namespace create %s: %v", ns, createErr)
		}
	} else {
		log.Printf("namespace %s already exists", ns)
	}

	// ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.sa,
			Namespace: ns,
			Labels:    labels,
		},
	}
	if _, err := a.kube.CoreV1().ServiceAccounts(ns).Get(ctx, names.sa, metav1.GetOptions{}); err == nil {
		_, _ = a.kube.CoreV1().ServiceAccounts(ns).Update(ctx, sa, metav1.UpdateOptions{})
	} else {
		_, _ = a.kube.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{})
	}

	// NetworkPolicy (deny ingress from other namespaces)
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.np,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: labels,
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{}, // Allow from all pods in this namespace
						},
					},
				},
			},
		},
	}
	if _, err := a.kube.NetworkingV1().NetworkPolicies(ns).Get(ctx, names.np, metav1.GetOptions{}); err == nil {
		_, _ = a.kube.NetworkingV1().NetworkPolicies(ns).Update(ctx, np, metav1.UpdateOptions{})
	} else {
		_, _ = a.kube.NetworkingV1().NetworkPolicies(ns).Create(ctx, np, metav1.CreateOptions{})
	}

	// Service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.svc,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(8081),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
	if _, err := a.kube.CoreV1().Services(ns).Get(ctx, names.svc, metav1.GetOptions{}); err == nil {
		_, _ = a.kube.CoreV1().Services(ns).Update(ctx, svc, metav1.UpdateOptions{})
	} else {
		_, _ = a.kube.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{})
	}

	// ConfigMap with config.yaml
	var cfg interface{}
	var cfgMap map[string]interface{}
	if len(scanner.ConfigJSON) > 0 {
		_ = json.Unmarshal(scanner.ConfigJSON, &cfg)
		_ = json.Unmarshal(scanner.ConfigJSON, &cfgMap)
	}

	// Ensure blacklist_events includes defaults to maintain consistency
	// regardless of what the Rust binary does or if the UI stripped them.
	defaults := []string{
		"AssumeRole",
		"*AssumeRole*",
		"Decrypt",
		"Encrypt",
		"GetCallerIdentity",
		"BatchGetImage",
		"FilterLogEvents",
		"UpdateInstanceInformation",
		"GenerateDataKey",
		"CreateLogStream",
	}
	if cfgMap == nil {
		cfgMap = make(map[string]interface{})
	}
	if existingBL, ok := cfgMap["blacklist_events"].([]interface{}); ok {
		// Merge defaults, avoiding duplicates
		existingSet := make(map[string]bool)
		for _, v := range existingBL {
			if s, ok := v.(string); ok {
				existingSet[s] = true
			}
		}
		for _, d := range defaults {
			if !existingSet[d] {
				cfgMap["blacklist_events"] = append(cfgMap["blacklist_events"].([]interface{}), d)
			}
		}
	} else {
		// No blacklist present, set defaults
		cfgMap["blacklist_events"] = defaults
	}

	// Use cfgMap for marshaling since we modified it
	yml, _ := yaml.Marshal(cfgMap)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.cm,
			Namespace: ns,
			Labels:    labels,
		},
		Data: map[string]string{
			"config.yaml": string(yml),
		},
	}
	if _, err := a.kube.CoreV1().ConfigMaps(ns).Get(ctx, names.cm, metav1.GetOptions{}); err == nil {
		_, _ = a.kube.CoreV1().ConfigMaps(ns).Update(ctx, cm, metav1.UpdateOptions{})
	} else {
		_, _ = a.kube.CoreV1().ConfigMaps(ns).Create(ctx, cm, metav1.CreateOptions{})
	}

	// Secret for credentials, if provided
	secretName := names.secret
	secretData := map[string][]byte{}

	// Load existing secret data to preserve keys not being updated
	if existing, err := a.kube.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{}); err == nil {
		if existing.Data != nil {
			secretData = existing.Data
		}
	}

	if req != nil {
		if req.AWSAccessKey != "" {
			secretData["AWS_ACCESS_KEY_ID"] = []byte(req.AWSAccessKey)
		}
		if req.AWSSecretKey != "" {
			secretData["AWS_SECRET_ACCESS_KEY"] = []byte(req.AWSSecretKey)
		}
		if req.AWSSession != "" {
			secretData["AWS_SESSION_TOKEN"] = []byte(req.AWSSession)
		}
		if req.JiraToken != "" {
			secretData["JIRA_TOKEN"] = []byte(req.JiraToken)
		}
		if req.GCPCredentials != "" {
			secretData["GCP_CREDENTIALS_JSON"] = []byte(req.GCPCredentials)
		}
	}

	if len(secretData) > 0 {
		log.Printf("applying secret for scanner %s in ns %s", scanner.Name, ns)
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: ns,
				Labels:    labels,
			},
			Data: secretData,
		}
		if _, err := a.kube.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{}); err == nil {
			_, _ = a.kube.CoreV1().Secrets(ns).Update(ctx, secret, metav1.UpdateOptions{})
		} else {
			_, _ = a.kube.CoreV1().Secrets(ns).Create(ctx, secret, metav1.CreateOptions{})
		}
	}

	// Non-secret envs
	regionEnv := func() string {
		extract := func(m map[string]interface{}) string {
			if v, ok := m["region"].(string); ok && strings.TrimSpace(v) != "" {
				return v
			}
			if nested, ok := m["aws"].(map[string]interface{}); ok {
				if v, ok := nested["region"].(string); ok && strings.TrimSpace(v) != "" {
					return v
				}
			}
			if nested, ok := m["kubernetes"].(map[string]interface{}); ok {
				if v, ok := nested["region"].(string); ok && strings.TrimSpace(v) != "" {
					return v
				}
			}
			return ""
		}
		if req != nil && req.Config != nil {
			var reqCfg map[string]interface{}
			_ = json.Unmarshal(req.Config, &reqCfg)
			if v := extract(reqCfg); v != "" {
				return v
			}
		}
		if v := extract(cfgMap); v != "" {
			return v
		}
		return ""
	}()
	jiraEmail := ""
	if req != nil && req.JiraEmail != "" {
		jiraEmail = req.JiraEmail
	}
	if jiraEmail == "" {
		if jraw, ok := cfgMap["jira"].(map[string]interface{}); ok {
			if v, ok := jraw["email"].(string); ok {
				jiraEmail = v
			}
		}
	}

	// Deployment
	replicas := int32(1)
	secretHash := hashMap(secretData)
	configHash := fmt.Sprintf("%x", sha256.Sum256(yml))
	hostADCPath := ""
	if a.mountADC && scanner.CloudProvider == "gcp" {
		// When using kind extraMounts, the ADC file is mounted into the node at this path.
		hostADCPath = "/var/secrets/adc.json"
	}

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.deploy,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						"noclickops/secret-hash": secretHash,
						"noclickops/config-hash": configHash,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: names.sa,
					Containers: []corev1.Container{
						{
							Name:            "scanner",
							Image:           a.image,
							ImagePullPolicy: "Never",
							Args:            []string{"--config", "/config/config.yaml"},
							VolumeMounts: func() []corev1.VolumeMount {
								mounts := []corev1.VolumeMount{{Name: "config", MountPath: "/config"}}
								if hostADCPath != "" {
									mounts = append(mounts, corev1.VolumeMount{
										Name:      "gcp-adc-host",
										MountPath: "/home/noclickops/.config/gcloud/application_default_credentials.json",
										ReadOnly:  true,
									})
								}
								return mounts
							}(),
							EnvFrom: func() []corev1.EnvFromSource {
								if len(secretData) == 0 {
									return nil
								}
								return []corev1.EnvFromSource{
									{
										SecretRef: &corev1.SecretEnvSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
										},
									},
								}
							}(),
							Env: func() []corev1.EnvVar {
								var envs []corev1.EnvVar
								if regionEnv != "" {
									envs = append(envs,
										corev1.EnvVar{Name: "AWS_REGION", Value: regionEnv},
										corev1.EnvVar{Name: "AWS_DEFAULT_REGION", Value: regionEnv},
									)
								}
								// if hostADCPath != "" {
								// 	envs = append(envs, corev1.EnvVar{
								// 		Name:  "GOOGLE_APPLICATION_CREDENTIALS",
								// 		Value: "/var/secrets/adc.json",
								// 	})
								// }
								if jiraEmail != "" {
									envs = append(envs, corev1.EnvVar{Name: "JIRA_EMAIL", Value: jiraEmail})
								}
								return envs
							}(),
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/api/v1/health",
										Port: intstr.FromInt(8081),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
							},
						},
					},
					Volumes: func() []corev1.Volume {
						vols := []corev1.Volume{
							{
								Name: "config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{Name: names.cm},
									},
								},
							},
						}
						if hostADCPath != "" {
							hostType := corev1.HostPathFile
							vols = append(vols, corev1.Volume{
								Name: "gcp-adc-host",
								VolumeSource: corev1.VolumeSource{
									HostPath: &corev1.HostPathVolumeSource{
										Path: hostADCPath,
										Type: &hostType,
									},
								},
							})
						}
						return vols
					}(),
				},
			},
		},
	}

	if _, err := a.kube.AppsV1().Deployments(ns).Get(ctx, names.deploy, metav1.GetOptions{}); err == nil {
		_, err = a.kube.AppsV1().Deployments(ns).Update(ctx, deploy, metav1.UpdateOptions{})
		return err
	}
	_, err := a.kube.AppsV1().Deployments(ns).Create(ctx, deploy, metav1.CreateOptions{})
	return err
}
