package roger

import (
	"io"
	"net"
	"strconv"
)

// RClient is the main Roger interface allowing interaction with R.
type RClient interface {

	// Eval evaluates an R command synchronously returning the resulting object and any possible error
	Eval(command string) (interface{}, error)

	// Evaluate evaluates an R command asynchronously. The returned channel will resolve to a Packet once the command has completed.
	Evaluate(command string) <-chan Packet

	// EvaluateSync evaluates an R command synchronously, resulting in a Packet.
	EvaluateSync(command string) Packet

	// VoidEval evalutes an R command without return any output, but error
	VoidEval(command string) error

	// GetReadWriteCloser obtains a connection to obtain data from the client
	GetReadWriteCloser() (io.ReadWriteCloser, error)
}

type roger struct {
	address  *net.TCPAddr
	user     string
	password string
}

// NewRClient creates a RClient which will run commands on the RServe server located at the provided host and port
func NewRClient(host string, port int64) (RClient, error) {
	return NewRClientWithAuth(host, port, "", "")
}

// NewRClientWithAuth creates a RClient with the specified credentials and RServe server details
func NewRClientWithAuth(host string, port int64, user, password string) (RClient, error) {
	addr, err := net.ResolveTCPAddr("tcp", host+":"+strconv.FormatInt(port, 10))
	if err != nil {
		return nil, err
	}

	return &roger{
		address:  addr,
		user:     user,
		password: password,
	}, nil
}

func (r *roger) EvaluateSync(command string) Packet {
	sess, err := newSession(r, r.user, r.password)
	if err != nil {
		return newErrorPacket(err)
	}
	defer sess.close()
	packet := sess.sendCommand(cmdEval, command+"\n")
	return packet
}

func (r *roger) VoidEval(command string) error {
	sess, err := newSession(r, r.user, r.password)
	if err != nil {
		return err
	}
	defer sess.close()
	err = sess.sendvoidCommand(command + "\n")
	return err
}

func (r *roger) Evaluate(command string) <-chan Packet {
	out := make(chan Packet)
	go func() {
		out <- r.EvaluateSync(command)
		close(out)
	}()
	return out
}

func (r *roger) Eval(command string) (interface{}, error) {
	return r.EvaluateSync(command).GetResultObject()
}

func (r *roger) GetReadWriteCloser() (io.ReadWriteCloser, error) {
	connection, err := net.DialTCP("tcp", nil, r.address)
	if err != nil {
		return nil, err
	}
	return connection, nil
}
