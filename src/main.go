package main

import (
	"embed"
	"io/fs"
	"log"

	"github.com/user/wisp/services"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Create services
	serverSvc := services.NewServerService()
	listenerSvc := services.NewListenerService(serverSvc)
	sessionSvc := services.NewSessionService(serverSvc)
	payloadSvc := services.NewPayloadService(serverSvc)
	fileServerSvc := services.NewFileServerService(serverSvc)

	// Strip the "frontend/dist" prefix so files are served from root
	staticAssets, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		log.Fatalf("Failed to get sub filesystem: %v", err)
	}

	app := application.New(application.Options{
		Name:        "Wisp",
		Description: "Wisp C2 Management Console",
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(staticAssets),
		},
		Services: []application.Service{
			application.NewService(serverSvc),
		application.NewService(listenerSvc),
		application.NewService(sessionSvc),
		application.NewService(payloadSvc),
		application.NewService(fileServerSvc),
	},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})

	// Set app reference for event emission
	serverSvc.SetApp(app)

	// Initialize the server
	if err := serverSvc.Initialize(); err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Resume the file server if it was running before the restart
	if err := fileServerSvc.Restore(); err != nil {
		log.Printf("Failed to restore file server: %v", err)
	}

	// Create main window
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "Wisp \u2014 C2 Management Console",
		Width:  1280,
		Height: 800,
		Mac: application.MacWindow{
			Backdrop: application.MacBackdropTranslucent,
		},
		URL: "/",
	})

	// Run the application
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}

	// Cleanup
	_ = fileServerSvc.StopFileServer()
	serverSvc.Shutdown()
}
