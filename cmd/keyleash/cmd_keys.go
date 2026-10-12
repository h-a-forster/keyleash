package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/secmem"
	"github.com/h-a-forster/keyleash/internal/vault"
)

var cmdAdd = &command{
	name:    "add",
	args:    "<provider> [--label name] [--stdin]",
	summary: "add a provider API key (hidden prompt or --stdin; never argv)",
	help: `
Stores a provider key in the encrypted vault. The key is read from a hidden
prompt, or from the first line of standard input with --stdin:

    keyleash add anthropic
    op read op://vault/anthropic/key | keyleash add anthropic --stdin

Putting the key itself on the command line is refused: arguments are
visible to other processes and saved in shell history.

Providers: anthropic, openai, openrouter, gemini. The very first key in
the vault is stored right away; any further key needs a step-up approval
(Windows Hello, or your passphrase or recovery code), so a process running
as you cannot slip its own key in. Each pass keeps the key it was issued
with; new passes use the provider's active key (its oldest key unless you
chose another with 'keyleash keys use <id>').`,
	run: runAdd,
}

func runAdd(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("add")
	label := fs.String("label", "default", "label for the key")
	fromStdin := fs.Bool("stdin", false, "read the key from stdin")
	pos, err := parseFlags(fs, args, true)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return usagef("add", "name the provider (%s)", strings.Join(provider.Names(), ", "))
	}
	if len(pos) > 1 {
		return usagef("add", "too many arguments; the key is never taken from the command line. "+
			"Run 'keyleash add %s' and paste it at the hidden prompt, or pipe it in with --stdin", sanitizeArg(pos[0]))
	}
	name := strings.ToLower(pos[0])
	if _, ok := provider.Get(name); !ok {
		return usagef("add", "unknown provider %q (want %s)", sanitizeArg(pos[0]), strings.Join(provider.Names(), ", "))
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	// Fail before asking for the key if the daemon cannot store it.
	sctx, cancel := withTimeout(ctx)
	st, err := c.Status(sctx)
	cancel()
	if err != nil {
		return err
	}
	if !st.Vault.Unlocked {
		return errLocked
	}
	return a.addKey(ctx, c, name, *label, *fromStdin)
}

// addKey reads an API key for providerName (hidden prompt or stdin) and
// stores it. The key is wiped after use and never printed.
func (a *app) addKey(ctx context.Context, c *client.Client, providerName, label string, fromStdin bool) error {
	raw, err := a.readSecret(fmt.Sprintf("Paste the %s key (input is hidden): ", providerName), fromStdin)
	defer func() { secmem.Wipe(raw) }()
	if err != nil {
		return err
	}
	key := trimSecret(raw)
	warn, err := checkKeyInput(providerName, key)
	if err != nil {
		return err
	}
	if warn != "" {
		fmt.Fprintln(a.stderr, "warning: "+warn)
	}
	var info client.KeyInfo
	err = a.withStepUp(ctx, c, func(ctx context.Context) error {
		var err error
		info, err = c.AddKey(ctx, providerName, label, key)
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Added %s key %q (id %s, fingerprint %s).\n", info.Provider, info.Label, info.ID, info.Fingerprint)
	if !info.Active && info.Kind == vault.KindAPIKey {
		fmt.Fprintf(a.stderr, "note: %s already has an active key; new passes keep using it until you run: keyleash keys use %s\n", info.Provider, info.ID)
	}
	return nil
}

// checkKeyInput validates a pasted key without ever echoing it. It returns
// an error for input that cannot be a provider key and a warning when the
// key does not look like one for this provider.
func checkKeyInput(providerName string, key []byte) (warning string, err error) {
	if len(key) == 0 {
		return "", errors.New("no key entered")
	}
	if len(key) > vault.MaxSecretSize {
		return "", errors.New("the key is too long")
	}
	// Inspect bytes only: converting the key to a string would leave an
	// unwipeable copy on the heap.
	if bytes.HasPrefix(key, []byte(pass.Prefix)) {
		return "", errors.New("that is a keyleash pass, not a provider key")
	}
	if recoveryCodeRE.Match(key) {
		return "", errors.New("that is a keyleash recovery code, not a provider key; copy the key from your provider's console")
	}
	for _, c := range key {
		if c <= ' ' || c >= 0x7f {
			return "", errors.New("the key contains spaces, control or non-ASCII characters; paste only the key")
		}
	}
	best, bestLen := "", 0
	for _, name := range provider.Names() {
		p, _ := provider.Get(name)
		for _, pre := range p.KeyPrefixes {
			if bytes.HasPrefix(key, []byte(pre)) && len(pre) > bestLen {
				best, bestLen = name, len(pre)
			}
		}
	}
	p, _ := provider.Get(providerName)
	switch {
	case best != "" && best != providerName:
		return fmt.Sprintf("this looks like a %s key, not a %s key; stored anyway (remove it with keyleash rm-key)", best, providerName), nil
	case best == "" && len(p.KeyPrefixes) > 0:
		return fmt.Sprintf("this key does not start with a known %s prefix (%s); stored anyway", providerName, strings.Join(p.KeyPrefixes, ", ")), nil
	}
	return "", nil
}

var cmdKeys = &command{
	name:    "keys",
	args:    "[--json] | use <id>",
	summary: "list stored keys (masked), or choose a provider's active key",
	help: `
  keyleash keys            list stored keys (masked: id, provider, label,
                           fingerprint; * marks each provider's active key)
  keyleash keys use <id>   make <id> its provider's active key: the key new
                           passes use (step-up approval; existing passes
                           keep the key they were issued with)`,
	run: func(ctx context.Context, a *app, args []string) error {
		fs := newFlagSet("keys")
		asJSON := fs.Bool("json", false, "print JSON")
		pos, err := parseFlags(fs, args, true)
		if err != nil {
			return err
		}
		use := len(pos) > 0 && pos[0] == "use"
		switch {
		case use && len(pos) != 2:
			return usagef("keys", "use takes exactly one key id (see 'keyleash keys')")
		case !use && len(pos) > 0:
			return usagef("keys", "unexpected argument")
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		defer c.Close()
		if use {
			var info client.KeyInfo
			err := a.withStepUp(ctx, c, func(ctx context.Context) error {
				var err error
				info, err = c.UseKey(ctx, pos[1])
				return err
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "New %s passes now use key %q (id %s, fingerprint %s).\n", info.Provider, info.Label, info.ID, info.Fingerprint)
			return nil
		}
		cctx, cancel := withTimeout(ctx)
		defer cancel()
		keys, err := c.Keys(cctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return a.printJSON(keys)
		}
		if len(keys) == 0 {
			fmt.Fprintln(a.stdout, "No keys stored. Add one with: keyleash add <provider>")
			return nil
		}
		now := time.Now()
		tw := newTable(a.stdout)
		fmt.Fprintln(tw, "ID\tPROVIDER\tKIND\tLABEL\tFINGERPRINT\tADDED")
		authenticated := true
		for _, k := range keys {
			authenticated = authenticated && k.Authenticated
			id := k.ID
			if k.Active {
				id += " *"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", id, k.Provider, k.Kind, k.Label, k.Fingerprint, fmtTime(k.Created, now))
		}
		tw.Flush()
		if !authenticated {
			fmt.Fprintln(a.stderr, "note: keyleash is locked, so this list is not verified yet.")
		}
		return nil
	},
}

var cmdRmKey = &command{
	name:    "rm-key",
	args:    "<id>",
	summary: "remove a stored key (step-up approval)",
	help: `
Removes a key from the vault. This needs a step-up approval (Windows Hello,
or your passphrase or recovery code). Get the id from 'keyleash keys'.
Passes issued with the key stop working. Removing a key does not revoke it
at the provider; rotate it there if it may have leaked.`,
	run: func(ctx context.Context, a *app, args []string) error {
		fs := newFlagSet("rm-key")
		pos, err := parseFlags(fs, args, true)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return usagef("rm-key", "give exactly one key id (see 'keyleash keys')")
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		defer c.Close()
		fmt.Fprintln(a.stderr, "Waiting for step-up approval...")
		if err := a.withStepUp(ctx, c, func(ctx context.Context) error { return c.RemoveKey(ctx, pos[0]) }); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Removed key %s.\n", pos[0])
		return nil
	},
}
