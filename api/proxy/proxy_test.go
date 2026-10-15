// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary-sdk/api/scopes"
	"github.com/hashicorp/boundary-sdk/api/targets"
	"github.com/mitchellh/copystructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()

	sessionAuth := testSessionAuth(t)
	l := &net.TCPListener{}

	tc := []struct {
		name        string
		authzString string
		transformFn func(*targets.SessionAuthorizationData) *targets.SessionAuthorizationData
		opts        []Option
		errContains string
		badOpts     bool
	}{
		{
			name: "base",
			opts: []Option{WithSessionAuthorizationData(sessionAuth)},
		},
		{
			name:        "bad options",
			opts:        []Option{WithSessionAuthorizationData(nil)},
			errContains: "data passed to WithSessionAuthorizationData is nil",
		},
		{
			name:        "no authz string",
			errContains: "empty session authorization token and object",
		},
		{
			name:        "bad authz string",
			authzString: "bad",
			errContains: "error turning authz token into authorization data",
		},
		{
			name: "no workers",
			transformFn: func(in *targets.SessionAuthorizationData) *targets.SessionAuthorizationData {
				in.WorkerInfo = []*targets.WorkerInfo{}
				return in
			},
			opts:        []Option{WithSessionAuthorizationData(sessionAuth)},
			errContains: "no workers found in authorization data",
		},
		{
			name: "with listener",
			opts: []Option{WithSessionAuthorizationData(sessionAuth), WithListener(l)},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			cpRaw, err := copystructure.Copy(sessionAuth)
			require.NoError(err)
			cp := sessionAuth
			if tt.transformFn != nil {
				cp = tt.transformFn(cpRaw.(*targets.SessionAuthorizationData))
				tt.opts = append(tt.opts, WithSessionAuthorizationData(cp))
			}
			p, err := New(context.Background(), tt.authzString, tt.opts...)
			if tt.errContains != "" {
				require.ErrorContains(err, tt.errContains)
				return
			}
			require.NoError(err)
			assert.Len(p.tofuToken, 20)
			assert.Equal(p.sessionAuthzData, sessionAuth)
			assert.True(p.listenAddrPort.IsValid())

			opts, err := getOpts(tt.opts...)
			require.NoError(err)
			if opts.WithListener == nil {
				assert.EqualValues(getDefaultOptions().WithListenAddrPort.Addr(), p.listenAddrPort.Addr())
			} else {
				assert.Equal(p.listener.Load(), l)
			}
			assert.Equal(p.connectionsLeft.Load(), cp.ConnectionLimit)
			assert.Equal(p.ConnectionsLeft(), cp.ConnectionLimit)
			assert.Equal(p.createTime, sessionAuth.CreatedTime)
			assert.Equal(p.SessionCreatedTime(), sessionAuth.CreatedTime)
			assert.Equal(p.expiration, sessionAuth.Expiration)
			assert.Equal(p.SessionExpiration(), sessionAuth.Expiration)
			assert.NotNil(p.ctx)
			assert.NotNil(p.cancel)
			assert.NotNil(p.transport)
		})
	}
}

func TestListenerAddr(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	sessionAuth := testSessionAuth(t)

	l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
	require.NoError(err)
	defer l.Close()
	expAddr := l.Addr().String()

	p, err := New(context.Background(), "", WithSessionAuthorizationData(sessionAuth), WithListener(l))
	require.NoError(err)

	// Listener should be cached so we should get the address of the listener
	assert.Equal(expAddr, p.ListenerAddress(context.Background()))
	assert.NotNil(p.cachedListenerAddress.Load())
	assert.Equal(expAddr, p.cachedListenerAddress.Load())
	// This should be returning the cached value now, which we already verified
	// above, but this will provide coverage
	assert.Equal(expAddr, p.ListenerAddress(context.Background()))

	// Now test the context cases
	p.cachedListenerAddress.Store("")
	p.listener = new(atomic.Value)

	// Check a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Equal("", p.ListenerAddress(ctx))

	// Pass in a new listener after a few seconds and ensure we block until
	// then, then receive a valid address
	start := time.Now()
	time.AfterFunc(3*time.Second, func() {
		p.listener.Store(l)
	})
	assert.Equal(expAddr, p.ListenerAddress(context.Background()))
	assert.WithinDuration(start.Add(3*time.Second), time.Now(), 500*time.Millisecond)
}

// fakeConn is a minimal net.Conn returns pre-configured local/remote addresses.
type fakeConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (c *fakeConn) LocalAddr() net.Addr  { return c.local }
func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }

func TestAllowConn(t *testing.T) {
	t.Parallel()

	localAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	peerAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
	lookupErr := errors.New("no matching socket")

	tests := []struct {
		name         string
		check        connOwnershipCheckFunc
		wantAllowed  bool
		wantRejected bool
		wantErr      error
	}{
		{
			name:        "no check configured allows",
			check:       nil,
			wantAllowed: true,
		},
		{
			name:        "check allows",
			check:       func(net.Conn) (bool, error) { return true, nil },
			wantAllowed: true,
		},
		{
			name:         "owner mismatch rejects",
			check:        func(net.Conn) (bool, error) { return false, nil },
			wantAllowed:  false,
			wantRejected: true,
			wantErr:      nil,
		},
		{
			name:         "lookup error rejects",
			check:        func(net.Conn) (bool, error) { return false, lookupErr },
			wantAllowed:  false,
			wantRejected: true,
			wantErr:      lookupErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			var (
				rejectedCalled    bool
				gotLocal, gotPeer net.Addr
				gotErr            error
			)
			opts := []Option{WithSessionAuthorizationData(testSessionAuth(t))}
			if tt.check != nil {
				opts = append(opts, WithConnOwnershipCheck(tt.check))
			}
			opts = append(opts, WithConnRejectedFunc(func(local, peer net.Addr, err error) {
				rejectedCalled = true
				gotLocal, gotPeer, gotErr = local, peer, err
			}))

			p, err := New(context.Background(), "", opts...)
			require.NoError(err)

			conn := &fakeConn{local: localAddr, remote: peerAddr}
			allowed := p.allowConn(conn)

			assert.Equal(tt.wantAllowed, allowed)
			assert.Equal(tt.wantRejected, rejectedCalled)
			if tt.wantRejected {
				assert.Equal(localAddr, gotLocal)
				assert.Equal(peerAddr, gotPeer)
				assert.Equal(tt.wantErr, gotErr)
			}
		})
	}
}

// TestStart_RejectedConnDoesNotBreakAcceptLoop starts a ClientProxy with a check that
// rejects the first connection and allows the second connection. It verifies:
//   - the first connection is rejected & closed by the server. connectionsLeft and activeConns
//     are unaffected, no dial to the worker is attempted.
//   - the second connection is still accepted, so the loop continued.
//
// A real worker isn't available here (api is a separate module from the main module, see the note
// at the top of proxy.go).
func TestStart_RejectedConnDoesNotBreakAcceptLoop(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	fakeWorkerLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer fakeWorkerLn.Close()

	workerDialCh := make(chan struct{}, 10)
	go func() {
		for {
			conn, err := fakeWorkerLn.Accept()
			if err != nil {
				return
			}
			workerDialCh <- struct{}{}
			conn.Close()
		}
	}()

	sessionAuthCopy, err := copystructure.Copy(testSessionAuth(t))
	require.NoError(err)
	sessionAuth := sessionAuthCopy.(*targets.SessionAuthorizationData)
	sessionAuth.WorkerInfo = []*targets.WorkerInfo{{Address: fakeWorkerLn.Addr().String()}}

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer clientLn.Close()

	// checkOwnership is a mock function which rejects the first connection, allow the second.
	var checkCalls atomic.Int32
	checkOwnership := func(net.Conn) (bool, error) {
		if checkCalls.Add(1) == 1 {
			return false, nil
		}
		return true, nil
	}

	rejectedCh := make(chan error, 1)
	rejectedFn := func(local, peer net.Addr, err error) {
		rejectedCh <- err
	}

	p, err := New(
		context.Background(),
		"",
		WithSessionAuthorizationData(sessionAuth),
		WithListener(clientLn),
		WithConnOwnershipCheck(checkOwnership),
		WithConnRejectedFunc(rejectedFn),
		WithSkipSessionTeardown(true),
	)
	require.NoError(err)

	startErrCh := make(chan error, 1)
	go func() { startErrCh <- p.Start() }()
	t.Cleanup(func() {
		p.cancel()
		<-startErrCh
	})

	initialConnsLeft := p.connectionsLeft.Load()
	initialActiveConns := p.activeConns.Load()

	// First connection:
	conn1, err := net.Dial("tcp", clientLn.Addr().String())
	require.NoError(err)
	defer conn1.Close()

	select {
	case gotErr := <-rejectedCh:
		assert.NoError(gotErr)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for connRejectedFn to be invoked")
	}

	require.NoError(conn1.SetReadDeadline(time.Now().Add(5 * time.Second)))
	_, err = conn1.Read(make([]byte, 1))
	assert.ErrorIs(err, io.EOF)

	assert.Equal(initialConnsLeft, p.connectionsLeft.Load())
	assert.Equal(initialActiveConns, p.activeConns.Load())
	assert.Len(workerDialCh, 0)

	// Second connection:
	conn2, err := net.Dial("tcp", clientLn.Addr().String())
	require.NoError(err)
	defer conn2.Close()

	select {
	case <-workerDialCh:
		// the accept loop continued
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a worker dial for the accepted connection")
	}
}

func testSessionAuth(t *testing.T) *targets.SessionAuthorizationData {
	sessionAuth := &targets.SessionAuthorizationData{
		SessionId: "s_1234567890",
		TargetId:  "ttcp_1234567890",
		Scope: &scopes.ScopeInfo{
			Id:            "p_1234567890",
			Type:          "project",
			ParentScopeId: "o_1234567890",
		},
		CreatedTime:     time.Now().Add(-time.Minute),
		Type:            "tcp",
		ConnectionLimit: 4,
		EndpointPort:    22,
		Expiration:      time.Now().Add(time.Minute),
		HostId:          "h_1234567890",
		Endpoint:        "localhost",
		WorkerInfo: []*targets.WorkerInfo{
			{
				Address: "localhost:9202",
			},
			{
				Address: "[::1]:9201",
			},
		},
	}

	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	template := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{"s_1234567890"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             sessionAuth.CreatedTime.Add(-1 * time.Minute),
		NotAfter:              sessionAuth.Expiration,
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	require.NoError(t, err)
	sessionAuth.Certificate = certBytes
	return sessionAuth
}
