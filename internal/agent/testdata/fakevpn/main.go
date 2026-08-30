// Command fakevpn imitates the interactive login of the VPN clients the agent
// supervises, so the prompt handling can be tested without a real gateway.
//
// It reproduces the two behaviours that matter and differ between them:
// aTrust prints prompts through the log package, which writes to standard
// error and terminates the line, while EasyConnect prints with fmt.Print to
// standard output and leaves the cursor on the same line.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	var (
		listen = flag.String("listen", "127.0.0.1:11080", "address to serve once logged in")
		style  = flag.String("style", "atrust", "atrust or easyconnect")
		want   = flag.String("code", "482915", "the code that satisfies the prompt")
		steps  = flag.String("steps", "sms", "comma separated prompts to ask: sms, totp, sso")
	)
	flag.Parse()

	log.SetFlags(0)
	fmt.Fprintln(os.Stderr, "fake VPN client starting")

	for _, step := range strings.Split(*steps, ",") {
		if !ask(strings.TrimSpace(step), *style, *want) {
			fmt.Fprintln(os.Stderr, "authentication failed")
			os.Exit(1)
		}
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "logged in, serving proxy")
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { defer c.Close(); io.Copy(io.Discard, c) }()
	}
}

func ask(step, style, want string) bool {
	switch step {
	case "sms":
		if style == "easyconnect" {
			// No newline: the real client leaves the cursor in place.
			fmt.Print("Please enter your SMS code: ")
		} else {
			log.Print("Please enter the SMS verification code: ")
		}
	case "totp":
		log.Print("Please enter the TOTP token: ")
	case "sso":
		log.Printf("Visit https://sso.example.com/login?id=abc to login, and catch the callback url")
		log.Println("Please enter the callback url:")
	default:
		return true
	}

	var got string
	if _, err := fmt.Scanln(&got); err != nil {
		fmt.Fprintln(os.Stderr, "read answer:", err)
		return false
	}
	if step == "sso" {
		return strings.HasPrefix(got, "https://")
	}
	return got == want
}
