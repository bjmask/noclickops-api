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
	"strings"
	"sync"
	"syscall"
	"time"

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
	DatabaseURL      string `yaml:"database_url"`
	AdminDatabaseURL string `yaml:"admin_database_url"`
	JWTSecret        string `yaml:"jwt_secret"`
	DeploymentType   string `yaml:"deployment_type"` // "process" or "docker"
	ScannerImage     string `yaml:"scanner_image"`
}

type Tenant struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Name      string    `json:"name" gorm:"uniqueIndex"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Users     []User
	Scanners  []Scanner
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
	db        *gorm.DB
	jwtSecret []byte
	procs     map[uint]*exec.Cmd
	mu        sync.Mutex
	deploy    string
	kube      *kubernetes.Clientset
	image     string
}

func main() {
	cfg := loadConfig()

	adminDSN := firstNonEmpty(os.Getenv("ADMIN_DATABASE_URL"), cfg.AdminDatabaseURL)
	targetDSN := firstNonEmpty(os.Getenv("DATABASE_URL"), cfg.DatabaseURL)
	jwtSecret := firstNonEmpty(os.Getenv("JWT_SECRET"), cfg.JWTSecret)
	scannerImage := firstNonEmpty(os.Getenv("SCANNER_IMAGE"), cfg.ScannerImage)
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

	if err := db.AutoMigrate(&Tenant{}, &User{}, &Scanner{}); err != nil {
		log.Fatalf("migration failed: %v", err)
	}

	app := &app{db: db, jwtSecret: []byte(jwtSecret), procs: make(map[uint]*exec.Cmd), deploy: strings.ToLower(cfg.DeploymentType), image: scannerImage}

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

	router := gin.Default()
	router.Static("/static", "web")
	router.StaticFile("/", "web/index.html")
	router.StaticFile("/dashboard", "web/dashboard.html")
	router.StaticFile("/dashboard.html", "web/dashboard.html")
	router.StaticFile("/scanners", "web/scanners.html")
	router.StaticFile("/scanners.html", "web/scanners.html")
	router.StaticFile("/findings", "web/findings.html")
	router.StaticFile("/findings.html", "web/findings.html")
	router.StaticFile("/docs", "web/docs.html")
	router.StaticFile("/docs.html", "web/docs.html")
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
	protected.GET("/scanners/:name/health", app.handleScannerHealth)
	protected.GET("/scanners/:name/logs", app.handleScannerLogs)
	protected.GET("/scanners/:name/findings", app.handleScannerFindings)
	protected.GET("/scanners/:name/kube-map", app.handleScannerKubeMap)

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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
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
	Name          string          `json:"name"`
	CloudProvider string          `json:"cloud_provider"`
	Config        json.RawMessage `json:"config"`
	Labels        json.RawMessage `json:"labels,omitempty"`
	AWSAccessKey  string          `json:"aws_access_key_id,omitempty"`
	AWSSecretKey  string          `json:"aws_secret_access_key,omitempty"`
	AWSSession    string          `json:"aws_session_token,omitempty"`
	JiraToken     string          `json:"jira_token,omitempty"`
	JiraEmail     string          `json:"jira_email,omitempty"`
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

	// Delete DB record
	if err := a.db.WithContext(c.Request.Context()).Delete(&scanner).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete scanner"})
		return
	}

	// Cleanup k8s resources if enabled
	if a.deploy == "kubernetes" && a.kube != nil {
		ns := namespaceFor(principal.TenantID, scanner.Name)
		go func() {
			grace := int64(0)
			_ = a.kube.AppsV1().Deployments(ns).Delete(context.Background(), "scanner", metav1.DeleteOptions{GracePeriodSeconds: &grace})
			_ = a.kube.CoreV1().ConfigMaps(ns).Delete(context.Background(), "scanner-config", metav1.DeleteOptions{})
			_ = a.kube.CoreV1().Secrets(ns).Delete(context.Background(), "scanner-secret", metav1.DeleteOptions{})
			_ = a.kube.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{})
			log.Printf("deleted k8s resources for scanner %s", scanner.Name)
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
	re := regexp.MustCompile(`[^a-zA-Z0-9_-]+`)
	s := re.ReplaceAllString(in, "-")
	return strings.Trim(s, "-")
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

	if a.deploy == "kubernetes" {
		ns := namespaceFor(principal.TenantID, scanner.Name)
		// Check deployment status
		if a.kube == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "kube client not initialized"})
			return
		}
		dep, err := a.kube.AppsV1().Deployments(ns).Get(c.Request.Context(), "scanner", metav1.GetOptions{})
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
	if a.deploy != "kubernetes" || a.kube == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "logs available only in kubernetes mode"})
		return
	}
	ns := namespaceFor(principal.TenantID, scanner.Name)
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
	if a.deploy != "kubernetes" || a.kube == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "findings available only in kubernetes mode"})
		return
	}
	ns := namespaceFor(principal.TenantID, scanner.Name)
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

func (a *app) handleScannerKubeMap(c *gin.Context) {
	principal := c.MustGet("principal").(*User)
	name := c.Param("name")
	var scanner Scanner
	if err := a.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND name = ?", principal.TenantID, name).
		First(&scanner).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scanner not found"})
		return
	}
	if a.deploy != "kubernetes" || a.kube == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "kube map available only in kubernetes mode"})
		return
	}
	ns := namespaceFor(principal.TenantID, scanner.Name)
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
		Suffix("api/v1/kubernetes/map").
		Do(c.Request.Context())
	bytes, err := raw.Raw()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "application/json", bytes)
}

func namespaceFor(tenantID uint, scannerName string) string {
	return fmt.Sprintf("scanner-%d-%s", tenantID, sanitize(scannerName))
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
	ns := namespaceFor(tenant.ID, scanner.Name)
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
	}

	// ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scanner",
			Namespace: ns,
			Labels:    labels,
		},
	}
	if _, err := a.kube.CoreV1().ServiceAccounts(ns).Get(ctx, "scanner", metav1.GetOptions{}); err == nil {
		_, _ = a.kube.CoreV1().ServiceAccounts(ns).Update(ctx, sa, metav1.UpdateOptions{})
	} else {
		_, _ = a.kube.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{})
	}

	// NetworkPolicy (deny ingress from other namespaces)
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-external-ingress",
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
	if _, err := a.kube.NetworkingV1().NetworkPolicies(ns).Get(ctx, "deny-external-ingress", metav1.GetOptions{}); err == nil {
		_, _ = a.kube.NetworkingV1().NetworkPolicies(ns).Update(ctx, np, metav1.UpdateOptions{})
	} else {
		_, _ = a.kube.NetworkingV1().NetworkPolicies(ns).Create(ctx, np, metav1.CreateOptions{})
	}

	// Service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scanner",
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
	if _, err := a.kube.CoreV1().Services(ns).Get(ctx, "scanner", metav1.GetOptions{}); err == nil {
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
			Name:      "scanner-config",
			Namespace: ns,
			Labels:    labels,
		},
		Data: map[string]string{
			"config.yaml": string(yml),
		},
	}
	if _, err := a.kube.CoreV1().ConfigMaps(ns).Get(ctx, "scanner-config", metav1.GetOptions{}); err == nil {
		_, _ = a.kube.CoreV1().ConfigMaps(ns).Update(ctx, cm, metav1.UpdateOptions{})
	} else {
		_, _ = a.kube.CoreV1().ConfigMaps(ns).Create(ctx, cm, metav1.CreateOptions{})
	}

	// Secret for credentials, if provided
	secretName := "scanner-secret"
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
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scanner",
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
					ServiceAccountName: "scanner",
					Containers: []corev1.Container{
						{
							Name:            "scanner",
							Image:           a.image,
							ImagePullPolicy: "Never",
							Args:            []string{"--config", "/config/config.yaml"},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "config", MountPath: "/config"},
							},
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
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: "scanner-config"},
								},
							},
						},
					},
				},
			},
		},
	}

	if _, err := a.kube.AppsV1().Deployments(ns).Get(ctx, "scanner", metav1.GetOptions{}); err == nil {
		_, err = a.kube.AppsV1().Deployments(ns).Update(ctx, deploy, metav1.UpdateOptions{})
		return err
	}
	_, err := a.kube.AppsV1().Deployments(ns).Create(ctx, deploy, metav1.CreateOptions{})
	return err
}
