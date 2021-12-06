package util

import (
	"bufio"
	"bytes"
	"os"
	"os/user"
	"strings"

	"github.com/sirupsen/logrus"
)

// LookupAllUsers returns a list of all users on the system.
// It only returns an error if /etc/password cannot be read.
func LookupAllUsers() ([]*user.User, error) {
	// Read /etc/passwd, but only the first entry on each line, which is the
	// username. Then pass that to user.Lookup to get the user struct.
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	var users []*user.User

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.IndexByte(line, ':')
		if idx == -1 {
			continue
		}
		username := line[:idx]
		u, err := user.Lookup(username)
		if err != nil {
			logrus.Errorf("error looking up user %s: %v", username, err)
			continue
		}
		users = append(users, u)
	}

	return users, nil
}
