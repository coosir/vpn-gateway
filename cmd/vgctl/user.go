package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/users"
)

func handleUserCommand(cfg *server.Config, args []string) error {
	if len(args) == 0 {
		return printUserHelp()
	}

	sub := args[0]
	switch sub {
	case "list", "ls":
		return runUserList(cfg)
	case "add":
		if len(args) < 3 {
			return errors.New("usage: vgctl user add <username> <password>")
		}
		return runUserAdd(cfg, args[1], args[2])
	case "passwd", "update", "set-password":
		if len(args) < 3 {
			return errors.New("usage: vgctl user passwd <username> <new-password>")
		}
		return runUserPasswd(cfg, args[1], args[2])
	case "del", "delete", "remove", "rm":
		if len(args) < 2 {
			return errors.New("usage: vgctl user delete <username>")
		}
		return runUserDelete(cfg, args[1])
	default:
		return fmt.Errorf("unknown user subcommand %q; use list, add, passwd, or delete", sub)
	}
}

func printUserHelp() error {
	fmt.Println("Usage: vgctl user <subcommand> [args...]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  list                          List all registered users")
	fmt.Println("  add <username> <password>     Create a new user")
	fmt.Println("  passwd <username> <password>  Update a user's password (disconnects active sessions)")
	fmt.Println("  delete <username>             Delete a user (disconnects active sessions immediately)")
	return nil
}

func getAPIClient(cfg *server.Config) (apiURL, token string, online bool) {
	_, apiPort, found := strings.Cut(cfg.APIListen, ":")
	if !found {
		apiPort = "8642"
	}
	apiURL = fmt.Sprintf("http://127.0.0.1:%s", apiPort)

	tok, err := readToken(cfg.StateDir)
	if err != nil {
		return "", "", false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/v1/health", nil)
	if err != nil {
		return apiURL, tok, false
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		return apiURL, tok, false
	}
	res.Body.Close()
	return apiURL, tok, true
}

func runUserList(cfg *server.Config) error {
	apiURL, token, online := getAPIClient(cfg)
	if online {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/v1/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			return fmt.Errorf("server error (%d): %s", res.StatusCode, strings.TrimSpace(string(b)))
		}
		var list []users.UserSummary
		if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
			return err
		}
		printUsers(list)
		return nil
	}

	// Offline fallback: load directly from state directory
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr, err := users.NewManager(cfg.StateDir, cfg.Users, log)
	if err != nil {
		return err
	}
	printUsers(mgr.List())
	return nil
}

func printUsers(list []users.UserSummary) {
	if len(list) == 0 {
		fmt.Println("no registered users found")
		return
	}
	fmt.Printf("%-20s %-25s %s\n", "USERNAME", "CREATED_AT", "UPDATED_AT")
	for _, u := range list {
		created := u.CreatedAt.Format("2006-01-02 15:04:05")
		updated := u.UpdatedAt.Format("2006-01-02 15:04:05")
		fmt.Printf("%-20s %-25s %s\n", u.Username, created, updated)
	}
}

func runUserAdd(cfg *server.Config, username, password string) error {
	apiURL, token, online := getAPIClient(cfg)
	if online {
		body, _ := json.Marshal(map[string]string{"username": username, "password": password})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/api/v1/users", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			return fmt.Errorf("failed to add user: %s", strings.TrimSpace(string(b)))
		}
		fmt.Printf("user %q added successfully (online)\n", username)
		return nil
	}

	// Offline fallback
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr, err := users.NewManager(cfg.StateDir, cfg.Users, log)
	if err != nil {
		return err
	}
	if err := mgr.Add(username, password); err != nil {
		return err
	}
	fmt.Printf("user %q added successfully (offline database updated)\n", username)
	return nil
}

func runUserPasswd(cfg *server.Config, username, password string) error {
	apiURL, token, online := getAPIClient(cfg)
	if online {
		body, _ := json.Marshal(map[string]string{"password": password})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPut, apiURL+"/api/v1/users/"+username, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			return fmt.Errorf("failed to update password: %s", strings.TrimSpace(string(b)))
		}
		fmt.Printf("password updated for user %q (active sessions disconnected)\n", username)
		return nil
	}

	// Offline fallback
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr, err := users.NewManager(cfg.StateDir, cfg.Users, log)
	if err != nil {
		return err
	}
	if err := mgr.UpdatePassword(username, password); err != nil {
		return err
	}
	fmt.Printf("password updated for user %q (offline database updated)\n", username)
	return nil
}

func runUserDelete(cfg *server.Config, username string) error {
	apiURL, token, online := getAPIClient(cfg)
	if online {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, apiURL+"/api/v1/users/"+username, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			return fmt.Errorf("failed to delete user: %s", strings.TrimSpace(string(b)))
		}
		fmt.Printf("user %q deleted successfully (active sessions disconnected)\n", username)
		return nil
	}

	// Offline fallback
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr, err := users.NewManager(cfg.StateDir, cfg.Users, log)
	if err != nil {
		return err
	}
	if err := mgr.Delete(username); err != nil {
		return err
	}
	fmt.Printf("user %q deleted successfully (offline database updated)\n", username)
	return nil
}
