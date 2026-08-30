package sangfor

import (
	"regexp"
	"strings"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// urlRE finds the login address printed just before a single sign-on prompt.
var urlRE = regexp.MustCompile(`https?://[^\s,]+`)

// prompts are the interactive questions zju-connect can ask.
//
// The upstream client asks them on standard input and blocks until answered,
// so each one has to become a contract challenge and the answer has to be
// written back. Markers are matched case-insensitively against a substring of
// the output, which survives the wording changing around them.
func prompts() []agent.Prompt {
	return []agent.Prompt{
		{
			Match: agent.Marker("enter the sms verification code"),
			Type:  contract.ChallengeSMS,
			Describe: func(line string, recent []string) contract.Challenge {
				return contract.Challenge{
					Type:   contract.ChallengeSMS,
					Prompt: "Enter the SMS verification code sent to your phone.",
				}
			},
		},
		{
			// EasyConnect words it differently from aTrust.
			Match: agent.Marker("enter your sms code"),
			Type:  contract.ChallengeSMS,
			Describe: func(line string, recent []string) contract.Challenge {
				return contract.Challenge{
					Type:   contract.ChallengeSMS,
					Prompt: "Enter the SMS verification code sent to your phone.",
				}
			},
		},
		{
			Match: agent.Marker("enter the totp token"),
			Type:  contract.ChallengeTOTP,
			Describe: func(line string, recent []string) contract.Challenge {
				return contract.Challenge{
					Type:   contract.ChallengeTOTP,
					Prompt: "Enter the current code from your authenticator app.",
				}
			},
		},
		{
			Match: agent.Marker("enter the radius token"),
			Type:  contract.ChallengePassword,
			Describe: func(line string, recent []string) contract.Challenge {
				return contract.Challenge{
					Type:   contract.ChallengePassword,
					Prompt: "Enter your RADIUS token.",
				}
			},
		},
		{
			Match: agent.Marker("enter rand code"),
			Type:  contract.ChallengeCaptcha,
			Describe: func(line string, recent []string) contract.Challenge {
				return contract.Challenge{
					Type:   contract.ChallengeCaptcha,
					Prompt: "Enter the characters shown in the gateway's image.",
				}
			},
		},
		{
			Match: agent.Marker("enter the graph check code"),
			Type:  contract.ChallengeCaptcha,
			Describe: func(line string, recent []string) contract.Challenge {
				return contract.Challenge{
					Type: contract.ChallengeCaptcha,
					// The upstream client wants a JSON document here rather
					// than the characters themselves, so say so plainly.
					Prompt: "Enter the graph check code as JSON, as the gateway's captcha helper produces it.",
				}
			},
		},
		{
			Match: agent.Marker("enter the callback url"),
			Type:  contract.ChallengeURL,
			Describe: func(line string, recent []string) contract.Challenge {
				ch := contract.Challenge{
					Type:   contract.ChallengeURL,
					Prompt: "Open the login page, sign in, then paste the address you are redirected to.",
				}
				// The login address is printed on the line before the prompt.
				for i := len(recent) - 1; i >= 0; i-- {
					if !strings.Contains(strings.ToLower(recent[i]), "visit") {
						continue
					}
					if m := urlRE.FindString(recent[i]); m != "" {
						ch.URL = m
						break
					}
				}
				return ch
			},
		},
	}
}
