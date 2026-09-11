/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package landlock

// Profile represents a Landlock ruleset for merge operations.
type Profile struct {
	// HandledAccessFS is the set of filesystem access rights handled by this
	// ruleset. Rights not listed here are not restricted.
	HandledAccessFS []FSAccessRight `json:"handledAccessFs,omitempty"`

	// HandledAccessNet is the set of network access rights handled by this
	// ruleset. Rights not listed here are not restricted.
	HandledAccessNet []NetAccessRight `json:"handledAccessNet,omitempty"`

	// Scoped is the set of IPC scope restrictions applied to this ruleset.
	// Scoped restrictions have no exceptions via rules; once scoped, access
	// outside the Landlock domain is fully blocked.
	Scoped []ScopeRight `json:"scoped,omitempty"`

	// PathRules defines filesystem access rules for specific path hierarchies.
	PathRules []PathRule `json:"pathRules,omitempty"`

	// NetRules defines network access rules for specific ports.
	NetRules []NetRule `json:"netRules,omitempty"`
}

// FSAccessRight represents a Landlock filesystem access right.
//
// The kernel rejects rights it does not know, so a profile should only use
// rights the target Landlock ABI supports. The rights below are available
// since ABI version 1 unless their documentation says otherwise.
type FSAccessRight string

const (
	// FSAccessExecute allows executing a file.
	FSAccessExecute FSAccessRight = "execute"

	// FSAccessWriteFile allows writing to a file.
	FSAccessWriteFile FSAccessRight = "write_file"

	// FSAccessReadFile allows reading a file.
	FSAccessReadFile FSAccessRight = "read_file"

	// FSAccessReadDir allows reading a directory.
	FSAccessReadDir FSAccessRight = "read_dir"

	// FSAccessRemoveDir allows removing a directory.
	FSAccessRemoveDir FSAccessRight = "remove_dir"

	// FSAccessRemoveFile allows removing a file.
	FSAccessRemoveFile FSAccessRight = "remove_file"

	// FSAccessMakeChar allows creating a character device.
	FSAccessMakeChar FSAccessRight = "make_char"

	// FSAccessMakeDir allows creating a directory.
	FSAccessMakeDir FSAccessRight = "make_dir"

	// FSAccessMakeReg allows creating a regular file.
	FSAccessMakeReg FSAccessRight = "make_reg"

	// FSAccessMakeSock allows creating a socket.
	FSAccessMakeSock FSAccessRight = "make_sock"

	// FSAccessMakeFIFO allows creating a FIFO.
	FSAccessMakeFIFO FSAccessRight = "make_fifo"

	// FSAccessMakeSym allows creating a symbolic link.
	FSAccessMakeSym FSAccessRight = "make_sym"

	// FSAccessMakeBlock allows creating a block device.
	FSAccessMakeBlock FSAccessRight = "make_block"

	// FSAccessRefer allows linking or renaming across directories.
	// Available since Landlock ABI version 2.
	FSAccessRefer FSAccessRight = "refer"

	// FSAccessTruncate allows truncating a file. Available since Landlock
	// ABI version 3.
	FSAccessTruncate FSAccessRight = "truncate"

	// FSAccessIOCTLDev allows ioctl on device files. Available since
	// Landlock ABI version 5.
	FSAccessIOCTLDev FSAccessRight = "ioctl_dev"

	// FSAccessResolveUnix allows resolving/connecting to pathname-based
	// UNIX domain sockets. Available since Landlock ABI version 9.
	FSAccessResolveUnix FSAccessRight = "resolve_unix"
)

// ScopeRight represents a Landlock IPC scope restriction. Scope
// restrictions are available since Landlock ABI version 6.
type ScopeRight string

const (
	// ScopeAbstractUnixSocket restricts connecting to abstract UNIX domain
	// sockets outside the Landlock domain.
	ScopeAbstractUnixSocket ScopeRight = "abstract_unix_socket"

	// ScopeSignal restricts sending signals to processes outside the
	// Landlock domain.
	ScopeSignal ScopeRight = "signal"
)

// NetAccessRight represents a Landlock network access right. Network rights
// match by port number; see each right for the ABI version it needs.
type NetAccessRight string

const (
	// NetAccessBindTCP allows binding a TCP socket. Available since
	// Landlock ABI version 4.
	NetAccessBindTCP NetAccessRight = "bind_tcp"

	// NetAccessConnectTCP allows connecting a TCP socket. Available since
	// Landlock ABI version 4.
	NetAccessConnectTCP NetAccessRight = "connect_tcp"

	// NetAccessBindUDP allows binding a UDP socket. Available since
	// Landlock ABI version 10.
	NetAccessBindUDP NetAccessRight = "bind_udp"

	// NetAccessConnectSendUDP allows setting the remote port of a UDP socket
	// via connect() or sending datagrams to a given remote port via
	// sendto()/sendmsg(). Available since Landlock ABI version 10.
	NetAccessConnectSendUDP NetAccessRight = "connect_send_udp"
)

// PathRule defines the access rights allowed for a specific path hierarchy.
type PathRule struct {
	// Path is the filesystem path hierarchy this rule applies to.
	Path string `json:"path"`

	// AccessFS is the set of filesystem access rights allowed under this path.
	AccessFS []FSAccessRight `json:"accessFs,omitempty"`
}

// NetRule defines the access rights allowed for a specific port.
type NetRule struct {
	// Port is the network port this rule applies to.
	Port uint16 `json:"port"`

	// AccessNet is the set of network access rights allowed for this port.
	AccessNet []NetAccessRight `json:"accessNet,omitempty"`
}

// abiVersion is a Landlock ABI version, as reported by
// landlock_create_ruleset(LANDLOCK_CREATE_RULESET_VERSION).
type abiVersion int

const (
	abiV1 abiVersion = iota + 1
	abiV2
	abiV3
	abiV4
	abiV5
	abiV6
	abiV7
	abiV8
	abiV9
	abiV10
)

// The tables below are the single source of the rights this package knows,
// each with the Landlock ABI version that introduced it. Validate accepts
// exactly the rights listed here, and tests enumerate them from here.
//
//nolint:gochecknoglobals // immutable lookup tables
var (
	fsAccessABI = map[FSAccessRight]abiVersion{
		FSAccessExecute:     abiV1,
		FSAccessWriteFile:   abiV1,
		FSAccessReadFile:    abiV1,
		FSAccessReadDir:     abiV1,
		FSAccessRemoveDir:   abiV1,
		FSAccessRemoveFile:  abiV1,
		FSAccessMakeChar:    abiV1,
		FSAccessMakeDir:     abiV1,
		FSAccessMakeReg:     abiV1,
		FSAccessMakeSock:    abiV1,
		FSAccessMakeFIFO:    abiV1,
		FSAccessMakeSym:     abiV1,
		FSAccessMakeBlock:   abiV1,
		FSAccessRefer:       abiV2,
		FSAccessTruncate:    abiV3,
		FSAccessIOCTLDev:    abiV5,
		FSAccessResolveUnix: abiV9,
	}

	netAccessABI = map[NetAccessRight]abiVersion{
		NetAccessBindTCP:        abiV4,
		NetAccessConnectTCP:     abiV4,
		NetAccessBindUDP:        abiV10,
		NetAccessConnectSendUDP: abiV10,
	}

	scopeABI = map[ScopeRight]abiVersion{
		ScopeAbstractUnixSocket: abiV6,
		ScopeSignal:             abiV6,
	}
)
