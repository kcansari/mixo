package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/kcansari/mixo/internal/cache"
	"github.com/kcansari/mixo/internal/config"
	"github.com/kcansari/mixo/internal/database"
	"github.com/kcansari/mixo/internal/handler"
	"github.com/kcansari/mixo/internal/logging"
	appmiddleware "github.com/kcansari/mixo/internal/middleware"
	"github.com/kcansari/mixo/internal/oauth"
	"github.com/kcansari/mixo/internal/routes"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/services"
	"github.com/kcansari/mixo/internal/session"
	"github.com/kcansari/mixo/internal/store"

	"github.com/joho/godotenv"
)

var addr = flag.String("addr", ":8080", "http service address")

func main() {
	flag.Parse()
	handler := run()

	server := &http.Server{Addr: *addr, Handler: handler}

	// Create context that listens for the interrupt signal
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run server in the background
	go func() {
		slog.Info("Server has been started successfully on", "port", *addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	// Listen for the interrupt signal
	<-ctx.Done()

	// Create shutdown context with 30-second timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Trigger graceful shutdown
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatal(err)
	}
}

func run() http.Handler {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("error loading .env file: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal("config error:", err)
	}

	opts := &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}
	if strings.EqualFold(cfg.App.Development, "production") {
		opts.AddSource = false
		opts.Level = slog.LevelInfo
	}

	base := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(&logging.ContextHandler{Handler: base})

	slog.SetDefault(logger)

	client, err := database.New(cfg.DB)
	if err != nil {
		log.Fatalf("failed connecting to db: %v", err)
	}

	err = database.Migrate(context.Background(), client)
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.ClientIPFromRemoteAddr)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(render.SetContentType(render.ContentTypeJSON))

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(60 * time.Second))

	userStore := store.NewUsers(client)
	refreshTokenStore := store.NewRefreshToken(client)

	cacheSvc, err := cache.NewRedisClient(cache.RedisConfig{
		Host:     cfg.DB.Redis.Host,
		Port:     cfg.DB.Redis.Port,
		Password: cfg.DB.Redis.Password,
		DB:       cfg.DB.Redis.DB,
	})

	if err != nil {
		log.Fatal("cache error:", err)
	}

	googleOAuth, err := oauth.NewGoogleOAuth(oauth.GoogleConfig{
		ClientID:     cfg.Google.ClientID,
		ClientSecret: cfg.Google.ClientSecret,
		RedirectURL:  cfg.Google.RedirectURL,
	})
	if err != nil {
		log.Fatal("google oauth error:", err)
	}

	cipher, err := security.NewCipher(cfg.App.CipherSecretKey)
	if err != nil {
		log.Fatal("cipher error:", err)
	}

	jwtSvc, err := security.NewJWTService(cfg.App.JWTSecret)
	if err != nil {
		log.Fatal("jwt service error:", err)
	}
	hmac := security.NewHmac(cfg.App.HMAC_SECRET_KEY)

	sessionManager := session.NewSession(jwtSvc, hmac, refreshTokenStore)

	authSvc := services.NewAuth(
		googleOAuth,
		cacheSvc,
		userStore,
		cipher,
		sessionManager,
	)

	//userSvc := services.NewUser(userStore)

	authHandler := handler.NewAuth(handler.Auth{
		AuthSvc:     authSvc,
		FrontendURL: cfg.App.FrontendURL,
	})

	authMiddleware := appmiddleware.NewAuth(sessionManager)

	r.Mount("/auth", routes.AuthResource{Auth: authHandler, AuthMiddleware: authMiddleware}.Routes())

	return r
}
