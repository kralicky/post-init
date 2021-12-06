package host

import (
	"net"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/sirupsen/logrus"
)

func GetNetworkInfo() *api.NetworkInfo {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	networkInfo := &api.NetworkInfo{}
	for _, intf := range interfaces {
		if intf.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrList, err := intf.Addrs()
		if err != nil {
			logrus.Errorf("Error getting addresses for interface %s: %s", intf.Name, err)
			continue
		}
		addrs := []*api.Addr{}
		for _, addr := range addrList {
			ip, ok := addr.(*net.IPNet)
			if !ok {
				logrus.Infof("Skipping non-IP address %s on interface %s", addr, intf.Name)
				continue
			}

			addrs = append(addrs, &api.Addr{
				Cidr:    ip.String(),
				Address: ip.IP.String(),
				Mask:    ip.Mask.String(),
			})
		}
		netIntf := &api.NetworkInterface{
			Device:    intf.Name,
			Up:        intf.Flags&net.FlagUp != 0,
			Addresses: addrs,
		}
		networkInfo.NetworkInterfaces =
			append(networkInfo.NetworkInterfaces, netIntf)
	}
	return networkInfo
}
