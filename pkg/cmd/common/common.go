package common

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"regexp"
	"syscall"

	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"golang.org/x/term"
)

// Prints welcome banner
func PrintWelcome() {
	color.New(color.FgGreen).Println("Welcome to the Trusted Platform!")
}

func PrintFirstStart() {
	fmt.Println("")
	fmt.Println("It looks like this is your first time starting the platform...")
	fmt.Println("")
	fmt.Println("Let's get started by setting the Certificate Authority and Platform credentials.")
	fmt.Println("")
}

// Prompts for input via STDIN using the given
// message as the user prompt.
func Prompt(prompt, message string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(message)
	fmt.Printf("%s $ ", prompt)
	str, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	return str
}

// Reads STDIN and returns the input as []byte
func ReadPassword(prompt string) []byte {
	fmt.Printf("%s> ", prompt)
	data, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()
	return data
}

// Prompt for password with confirmation of the typed password
func ConfirmPassword(prompt, passwordPolicyPattern string) (keystore.Password, error) {

	fmt.Print("Enter Password")
	password := ReadPassword(prompt)
	fmt.Println()

	fmt.Println("Confirm Password")
	confirm := ReadPassword(prompt)

	if bytes.Compare(password, confirm) != 0 {
		return nil, common.ErrPasswordsDontMatch
	}

	regex, err := regexp.Compile(passwordPolicyPattern)
	if err != nil {
		log.Fatal(err)
	}

	if !regex.MatchString(string(password)) {
		log.Fatal(fmt.Sprintf("%s: %s", common.ErrPasswordComplexity, passwordPolicyPattern))
	}

	return keystore.NewClearPassword(password), nil
}
