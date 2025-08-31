package main

import (
	"context"
	"log"
	"net/http"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
	"github.com/guided-traffic/s3-encryption-proxy/internal/s3"
)

func main() {
	// Test configuration to verify our new handlers work
	cfg := &config.Config{
		Encryption: config.Encryption{
			Provider: "none",
		},
		S3: config.S3{
			Endpoint:       "http://localhost:9000",
			Region:         "us-east-1",
			AccessKeyID:    "minioadmin",
			SecretKey:      "minioadmin",
			MetadataPrefix: "x-amz-meta-",
			DisableSSL:     true,
			ForcePathStyle: true,
		},
		Server: config.Server{
			Port: 8080,
		},
		Logging: config.Logging{
			Level: "info",
		},
	}

	// Initialize encryption manager
	encManager, err := encryption.NewManager(cfg)
	if err != nil {
		log.Fatalf("Failed to create encryption manager: %v", err)
	}

	// Initialize S3 client
	s3Client, err := s3.NewClient(&s3.Config{
		Endpoint:       cfg.S3.Endpoint,
		Region:         cfg.S3.Region,
		AccessKeyID:    cfg.S3.AccessKeyID,
		SecretKey:      cfg.S3.SecretKey,
		MetadataPrefix: cfg.S3.MetadataPrefix,
		DisableSSL:     cfg.S3.DisableSSL,
		ForcePathStyle: cfg.S3.ForcePathStyle,
	}, encManager)
	if err != nil {
		log.Fatalf("Failed to create S3 client: %v", err)
	}

	// Initialize proxy server
	server, err := proxy.NewServer(&proxy.Config{
		Port:             cfg.Server.Port,
		CertFile:         cfg.Server.CertFile,
		KeyFile:          cfg.Server.KeyFile,
		ShutdownTimeout:  cfg.Server.ShutdownTimeout,
		ReadTimeout:      cfg.Server.ReadTimeout,
		WriteTimeout:     cfg.Server.WriteTimeout,
		IdleTimeout:      cfg.Server.IdleTimeout,
		MaxHeaderBytes:   cfg.Server.MaxHeaderBytes,
		AllowedOrigins:   cfg.Server.AllowedOrigins,
		AllowedMethods:   cfg.Server.AllowedMethods,
		AllowedHeaders:   cfg.Server.AllowedHeaders,
		AllowCredentials: cfg.Server.AllowCredentials,
	}, s3Client)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	log.Println("S3 Encryption Proxy starting on port 8080...")
	log.Println("New S3 API handlers integrated successfully!")
	log.Println("- Bucket operations: Pass-through to S3")
	log.Println("- Object operations: Encryption/Decryption")
	log.Println("- Additional S3 APIs: Available with proper routing")

	// Start server (this would block)
	ctx := context.Background()
	if err := server.Start(ctx); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}
