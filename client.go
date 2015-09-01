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

	// GetReadWriteCloser obtains a connection to obtain data from the client
	GetReadWriteCloser() (io.ReadWriteCloser, error)

	//Close connection
	Close()
}

type roger struct {
	address  *net.TCPAddr
	sess     *session
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

	rClient := &roger{
		address:  addr,
		user:     user,
		password: password,
	}

	sess, err := newSession(rClient, user, password)
	if err != nil {
		return nil, err
	}

	rClient.sess = sess

	if _, err = rClient.Eval("'Test session connection'"); err != nil {
		return nil, err
	}
	return rClient, nil
}

//Close R client connection
func (r *roger) Close() {
	r.sess.close()
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

func (r *roger) Evaluate(command string) <-chan Packet {
	out := make(chan Packet)
	go func() {
		out <- r.EvaluateSync(command)
		close(out)
	}()
	return out
}

func (r *roger) Eval(command string) (interface{}, error) {
	packet := r.sess.sendCommand(cmdEval, command+"\n")
	return packet.GetResultObject()
}

func (r *roger) GetReadWriteCloser() (io.ReadWriteCloser, error) {
	connection, err := net.DialTCP("tcp", nil, r.address)
	if err != nil {
		return nil, err
	}
	return connection, nil
}
