package host

import (
	"bufio"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func GetPreferredHostPublicKey() ssh.PublicKey {
	algorithmsInPreferredOrder, err := getHostKeyAlgorithms()
	if err != nil {
		logrus.Fatal(err)
	}
	// Read all files in /etc/ssh/ssh_host_*_key.pub
	entries, err := os.ReadDir("/etc/ssh")
	if err != nil {
		logrus.Fatalf("Failed to read /etc/ssh: %v", err)
	}
	keys := []ssh.PublicKey{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(entry.Name(), "ssh_host_") && strings.HasSuffix(entry.Name(), "_key.pub") {
			logrus.Infof("Reading host public key from /etc/ssh/%s", entry.Name())
			data, err := os.ReadFile(filepath.Join("/etc/ssh", entry.Name()))
			if err != nil {
				logrus.Fatalf("Failed to read host public key %s: %v", entry.Name(), err)
			}
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				logrus.Fatalf("Failed to parse host public key %s: %v", entry.Name(), err)
			}
			keys = append(keys, pubKey)
		}
	}
	if len(keys) == 0 {
		logrus.Fatal("No host public keys found in /etc/ssh")
	}
	// Find the first algorithm that matches a key
	for _, algorithm := range algorithmsInPreferredOrder {
		for _, key := range keys {
			if key.Type() == algorithm {
				return key
			}
		}
	}

	// nothing found, something is wrong
	logrus.Fatal("No host public keys found that match the available host key algorithms")
	return nil
}

type authorizedKeyFile struct {
	Path string
	User string
}

func authorizedKeyFiles() []authorizedKeyFile {
	keyFiles := []authorizedKeyFile{}
	if euid := os.Geteuid(); euid != 0 {
		currentUser, err := user.LookupId(strconv.Itoa(euid))
		if err != nil {
			logrus.Fatalf("Failed to lookup current user: %v", err)
		}
		keyFilePath := filepath.Join(currentUser.HomeDir, ".ssh/authorized_keys")
		if _, err := os.Stat(keyFilePath); err == nil {
			keyFiles = append(keyFiles, authorizedKeyFile{
				Path: filepath.Join(currentUser.HomeDir, ".ssh/authorized_keys"),
				User: currentUser.Username,
			})
		}
	} else {
		rootAuthorizedKeysPath := "/root/.ssh/authorized_keys"
		if _, err := os.Stat(rootAuthorizedKeysPath); err == nil {
			keyFiles = append(keyFiles, authorizedKeyFile{
				Path: "/root/.ssh/authorized_keys",
				User: "root",
			})
		}
		allUsers, err := util.LookupAllUsers()
		if err != nil {
			logrus.Fatalf("Failed to look up users: %v", err)
		}
		for _, user := range allUsers {
			keyFilePath := filepath.Join(user.HomeDir, ".ssh/authorized_keys")
			if _, err := os.Stat(keyFilePath); err == nil {
				keyFiles = append(keyFiles, authorizedKeyFile{
					Path: keyFilePath,
					User: user.Name,
				})
			}
		}
	}
	return keyFiles
}

// GetAuthorizedKeys returns a list of all authorized keys on the system.
// If the current user is not root, keys are read from the current user's
// authorized_keys file only.
// If the current user is root, keys are read from all authorized_keys files
// from all users including root.
func GetAuthorizedKeys() []*api.AuthorizedKey {
	authorizedKeys := []*api.AuthorizedKey{}
	files := authorizedKeyFiles()
	for _, file := range files {
		f, err := os.Open(file.Path)
		if err != nil {
			logrus.Errorf("Failed to open authorized_keys file %s: %v", file, err)
			continue
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Bytes()
			if strings.TrimSpace(string(line)) == "" {
				continue
			}
			key, comment, opts, _, err := ssh.ParseAuthorizedKey(line)
			if err != nil {
				logrus.Errorf("Error when parsing entry in authorized_keys file %s: %v", file, err)
				continue
			}
			authorizedKeys = append(authorizedKeys, &api.AuthorizedKey{
				User:        file.User,
				Type:        key.Type(),
				Fingerprint: ssh.FingerprintSHA256(key),
				Comment:     comment,
				Options:     opts,
			})
		}
	}
	return authorizedKeys
}

func getHostKeyAlgorithms() ([]string, error) {
	cmd := exec.Command("ssh", "-Q", "HostKeyAlgorithms")
	algorithms, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(algorithms)), "\n"), nil
}
