package host

import (
	"syscall"

	"github.com/kralicky/post-init/pkg/api"
)

func int8ArrayToString(int8Buf []int8) string {
	buf := make([]byte, 0, len(int8Buf))
	for _, c := range int8Buf {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

func GetUnameInfo() *api.UnameInfo {
	utsname := &syscall.Utsname{}
	if err := syscall.Uname(utsname); err != nil {
		panic(err)
	}
	return &api.UnameInfo{
		KernelName:    int8ArrayToString(utsname.Sysname[:]),
		Hostname:      int8ArrayToString(utsname.Nodename[:]),
		KernelRelease: int8ArrayToString(utsname.Release[:]),
		KernelVersion: int8ArrayToString(utsname.Version[:]),
		Machine:       int8ArrayToString(utsname.Machine[:]),
	}
}
