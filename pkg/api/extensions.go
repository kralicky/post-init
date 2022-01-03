package api

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

func (a *Announcement) FilterAccepts(m *BasicFilter) bool {
	switch m.Operator {
	case Operator_Or:
		return matchAuthorizedKey(a.AuthorizedKeys, m.HasAuthorizedKey) ||
			matchIPAddress(a.Network.NetworkInterfaces, m.HasIPAddress) ||
			matchHostname(a.Uname.Hostname, m.HasHostname)
	case Operator_And:
		return matchAuthorizedKey(a.AuthorizedKeys, m.HasAuthorizedKey) &&
			matchIPAddress(a.Network.NetworkInterfaces, m.HasIPAddress) &&
			matchHostname(a.Uname.Hostname, m.HasHostname)
	}
	return false
}

func matchAuthorizedKey(keys []*AuthorizedKey, match string) bool {
	for _, k := range keys {
		if k.Fingerprint == match {
			return true
		}
	}
	return false
}

func matchIPAddress(ifaces []*NetworkInterface, match string) bool {
	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			if strings.Contains(match, "/") {
				if addr.Cidr == match {
					return true
				}
			} else {
				if addr.Address == match {
					return true
				}
			}
		}
	}
	return false
}

func matchHostname(hostname, match string) bool {
	return hostname == match
}

func (a *Announcement) Fingerprint() (string, error) {
	pubKey, err := ssh.ParsePublicKey(a.PreferredHostPublicKey)
	if err != nil {
		return "", err
	}
	fingerprint := ssh.FingerprintSHA256(pubKey)
	return fingerprint, nil
}
