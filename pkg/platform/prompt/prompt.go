package prompt

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/fatih/color"
	"golang.org/x/term"
)

const (
	userPrompt = "trusted-platform> $ "
)

func PrintBanner(version string) {
	color.New(color.FgGreen).Printf("Trusted Platform v%s\n\n", version)
}

func PasswordPrompt(message string) []byte {
	fmt.Printf("%s: \n", message)
	fmt.Printf(userPrompt)
	sopin, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()
	return sopin
}

func SOPin() []byte {
	return PasswordPrompt("Security Officer PIN")
}

func Pin() []byte {
	return PasswordPrompt("User PIN")
}

func KeyPassword() []byte {
	return PasswordPrompt("Key Password")
}

func Prompt(message string) []byte {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%s: \n", message)
	fmt.Printf(userPrompt)

	response, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	return []byte(response)
}

func NoOpPrompt() []byte {
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	return []byte(response)
}
