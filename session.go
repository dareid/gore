package roger

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"strings"

	"math"
)

// Session is an interface to send commands to an RServe session. Sessions must be closed after use.
type Session interface {

	// Sends a command to RServe which is evaluated synchronously resulting in a Packet.
	SendCommand(command string) Packet

	Assign(symbol string, cont interface{}) error

	// Close closes a RServe session. Sessions must be closed after use.
	Close()

	//StructToR assign struct field values to R
	StructToR(interface{}) error
}

type authType int

const (
	atPlain authType = 1
	atCrypt authType = 2
)

type session struct {
	readWriteClose     io.ReadWriteCloser
	readWriter         *bufio.ReadWriter
	authReq            bool
	authType           authType
	key                string
	connected          bool
	rServeIDSig        string
	rServeProtocol     string
	rServeCommProtocol string

	user     string
	password string
}

func newSession(readWriteCloser io.ReadWriteCloser, user, password string) (*session, error) {
	buffRead := bufio.NewReader(readWriteCloser)
	buffWrite := bufio.NewWriter(readWriteCloser)
	sess := &session{
		readWriteClose: readWriteCloser,
		readWriter:     bufio.NewReadWriter(buffRead, buffWrite),
		user:           user,
		password:       password,
	}
	err := sess.handshake()
	return sess, err
}

func (s *session) Close() {
	s.connected = false
	s.readWriter = nil
	if s.readWriteClose != nil {
		s.readWriteClose.Close()
	}
	s.readWriteClose = nil
}

func (s *session) readNBytes(bytes int) []byte {
	ret := make([]byte, bytes)
	for v := 0; v < bytes; v++ {
		ret[v], _ = s.readWriter.ReadByte()
	}
	return ret
}

func (s *session) toCharset(str string) []byte {
	return []byte(str)
}

func (s *session) parseInitialMessage() error {
	s.rServeIDSig = string(s.readNBytes(4))
	s.rServeProtocol = string(s.readNBytes(4))
	s.rServeCommProtocol = string(s.readNBytes(4))
	for i := 12; i < 32; i += 4 {
		attr := s.readNBytes(4)
		attrString := string(attr)
		if attrString == "ARpt" && s.authReq == false {
			s.authReq = true
			s.authType = atPlain
		}
		if attrString == "ARuc" {
			s.authReq = true
			s.authType = atCrypt
		}
		if attrString[0] == 'K' {
			s.key = attrString[1:3]
		}
	}

	if s.rServeCommProtocol == "" ||
		s.rServeIDSig == "" ||
		s.rServeProtocol == "" {
		return errors.New("Handshake failed")
	}
	return nil
}

func (s *session) login() error {
	if s.authReq == false {
		return nil
	}
	if s.authReq == true && (s.user == "" || s.password == "") {
		return errors.New("Authentication is required and no credentials have been specified")
	}
	if s.key == "" {
		s.key = "rs"
	}
	cmd := s.user + "\n" + s.password
	if s.authType == atCrypt {
		cmd = s.user + "\n" + crypt(s.password, s.key)
	}

	packet := s.sendCommand(cmdLogin, cmd)
	if packet.IsError() {
		_, err := packet.GetResultObject()
		return errors.New("Authentication failed: " + err.Error())
	}
	return nil
}

func (s *session) handshake() error {
	err := s.parseInitialMessage()
	if err != nil {
		return err
	}

	err = s.login()
	if err != nil {
		return err
	}

	s.connected = true

	if s.rServeCommProtocol != "QAP1" ||
		s.rServeIDSig != "Rsrv" ||
		s.rServeProtocol != "0103" {
		log.Println("The version of RServe installed is not officially supported. Please consider upgrading to the latest version of RServe.")
	}
	return nil
}

func (s *session) setHdr(valueType dataType, valueLength int, buf []byte) {
	buf[0] = byte(valueType)
	buf[1] = byte(valueLength & 255)
	buf[2] = byte((valueLength & 0xff00) >> 8)
	buf[3] = byte((valueLength & 0xff0000) >> 16)
}

func (s *session) setHdrOffset(valueType dataType, valueLength int, buf []byte, o int) {
	if valueLength > 0xfffff0 {
		buf[o] = byte((valueType & 255) | dtLarge)
		o++
	} else {
		buf[o] = byte(valueType & 255)
		o++
	}
	buf[o] = byte(valueLength & 255)
	o++
	buf[o] = byte((valueLength & 0xff00) >> 8)
	o++
	buf[o] = byte((valueLength & 0xff0000) >> 16)
	o++
	if valueLength > 0xfffff0 {
		buf[o] = byte((valueLength & 0xff000000) >> 24)
		o++
		buf[o] = 0
		o++
		buf[o] = 0
		o++
		buf[o] = 0
		o++
	}
}

func (s *session) prepareStringCommand(cmd string) []byte {
	cmd = strings.Replace(cmd, "\r", "\n", -1) //avoid potential issue when loading external r script block
	rawCmdBytes := s.toCharset(cmd)
	requiredLength := len(rawCmdBytes) + 1
	//make sure length is divisible by 4
	if requiredLength&3 > 0 {
		requiredLength = (requiredLength & 0xfffffc) + 4
	}
	cmdBytes := make([]byte, requiredLength+5)
	for i := 0; i < len(rawCmdBytes); i++ {
		cmdBytes[4+i] = rawCmdBytes[i]
	}
	s.setHdr(dtString, requiredLength, cmdBytes)
	return cmdBytes
}

func (s *session) exeCommand(cmdType command, cmd string) {
	cmdBytes := s.prepareStringCommand(cmd)
	buf := new(bytes.Buffer)
	//command
	binary.Write(buf, binary.LittleEndian, int32(cmdType))
	//length of message (bits 0-31)
	binary.Write(buf, binary.LittleEndian, int32(len(cmdBytes)))
	//offset of message part
	binary.Write(buf, binary.LittleEndian, int32(0))
	// length of message (bits 32-63)
	binary.Write(buf, binary.LittleEndian, int32(0))
	binary.Write(buf, binary.LittleEndian, cmdBytes)

	s.readWriter.Write(buf.Bytes())
	s.readWriter.Flush()
}

func (s *session) request(cmdType command, cont []byte, offset int, length int) Packet {
	if cont != nil {
		if offset >= len(cont) {
			cont = nil
			length = 0
		} else if length > (len(cont) - offset) {
			length = len(cont) - offset
		}
	}
	if offset < 0 {
		offset = 0
	}
	if length < 0 {
		length = 0
	}

	contlen := 0
	if cont != nil {
		contlen = length
	}

	hdr := make([]byte, 16)
	s.setInt(int(cmdType), hdr, 0)
	s.setInt(contlen, hdr, 4)
	for i := 8; i < 16; i++ {
		hdr[i] = 0
	}

	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, hdr)
	binary.Write(buf, binary.LittleEndian, cont)

	s.readWriter.Write(buf.Bytes())
	s.readWriter.Flush()

	return s.readResponse()
}

func (s *session) readResponse() Packet {
	rep := binary.LittleEndian.Uint32(s.readNBytes(4))
	r1 := binary.LittleEndian.Uint32(s.readNBytes(4))
	s.readNBytes(8)

	if r1 <= 0 {
		return newPacket(int(rep), nil)
	}

	results := s.readNBytes(int(r1))
	return newPacket(int(rep), results)
}

func (s *session) sendCommand(cmdType command, cmd string) Packet {
	if s.connected == false && cmdType != cmdLogin {
		return newErrorPacket(errors.New("Session was previously closed"))
	}
	s.exeCommand(cmdType, cmd)
	return s.readResponse()
}

func (s *session) SendCommand(cmd string) Packet {
	return s.sendCommand(cmdEval, cmd)
}

func (s *session) Eval(cmd string) (interface{}, error) {
	return s.sendCommand(cmdEval, cmd).GetResultObject()
}

func (s *session) Assign(symbol string, value interface{}) (err error) {
	switch value.(type) {
	case []float64:
		log.Printf("session assign, type is []float64, value is %v\n", value)
		err = s.AssignDoubleArray(symbol, value.([]float64))
	case []int32:
		log.Printf("session assign, type is []int32, value is %v\n", value)
		err = s.AssignIntArray(symbol, value.([]int32))
	case []string:
		log.Printf("session assign, type is []string, value is %v\n", value)
		err = s.AssignStrArray(symbol, value.([]string))
	case []byte:
		log.Printf("session assign, type is []byte, value is %v\n", value)
		err = s.AssignByteArray(symbol, value.([]byte))
	case string:
		log.Printf("session assign, type is string, value is %v\n", value)
		err = s.AssignStr(symbol, value.(string))
	default:
		log.Printf("session assign, type is not supported\n")
	}
	return
}

func (s *session) setInt(v int, buf []byte, o int) {
	buf[o] = byte(v & 255)
	o++
	buf[o] = byte((v & 0xff00) >> 8)
	o++
	buf[o] = byte((v & 0xff0000) >> 16)
	o++
	buf[o] = byte((v & 0xff000000) >> 24)
	o++
}

func (s *session) setLong(l int64, buf []byte, o int) {
	s.setInt(int(l&0xffffffff), buf, o)
	s.setInt(int(l>>32), buf, o+4)
}

func (s *session) AssignDoubleArray(symbol string, value []float64) (err error) {
	rl := len(value)*8 + 4
	if rl > 0xfffff0 {
		rl += 4
	}
	symn := []byte(symbol)
	sl := len(symn) + 1
	if (sl & 3) > 0 {
		sl = (sl & 0xfffffc) + 4
	}

	//	log.Println("rl=", rl, "sl=", sl)

	var rq []byte

	if rl > 0xfffff0 {
		rq = make([]byte, sl+rl+12)
	} else {
		rq = make([]byte, sl+rl+8)
	}

	ic := 0
	for ; ic < len(symn); ic++ {
		rq[ic+4] = symn[ic]
	}
	for ic < sl {
		rq[ic+4] = 0
		ic++
	}

	s.setHdrOffset(dtString, sl, rq, 0)
	s.setHdrOffset(dtSexp, rl, rq, sl+4)

	var off int
	if rl > 0xfffff0 {
		off = sl + 12
		s.setHdrOffset(33, rl-8, rq, off)
		off += 8
	} else {
		off = sl + 8
		s.setHdrOffset(33, rl-4, rq, off)
		off += 4
	}

	i := 0
	io := off
	for i < len(value) {
		//	log.Println("len(rq)=", len(rq), "i=", i, "io=", io, "value[i]=", value[i])
		s.setLong(int64(math.Float64bits(value[i])), rq, io)
		i++
		io += 8
	}

	rp := s.request(cmdSetSexp, rq, 0, len(rq))
	if rp != nil && rp.IsOk() {
		return
	}
	err = errors.New("Assign failed")
	return
}

func (s *session) AssignIntArray(symbol string, value []int32) (err error) {
	rl := len(value)*4 + 4
	if rl > 0xfffff0 {
		rl += 4
	}
	symn := []byte(symbol)
	sl := len(symn) + 1
	if (sl & 3) > 0 {
		sl = (sl & 0xfffffc) + 4
	}

	//log.Println("rl=", rl, "sl=", sl)

	var rq []byte

	if rl > 0xfffff0 {
		rq = make([]byte, sl+rl+12)
	} else {
		rq = make([]byte, sl+rl+8)
	}

	ic := 0
	for ; ic < len(symn); ic++ {
		rq[ic+4] = symn[ic]
	}
	for ic < sl {
		rq[ic+4] = 0
		ic++
	}

	s.setHdrOffset(dtString, sl, rq, 0)
	s.setHdrOffset(dtSexp, rl, rq, sl+4)

	var off int
	if rl > 0xfffff0 {
		off = sl + 12
		s.setHdrOffset(32, rl-8, rq, off)
		off += 8
	} else {
		off = sl + 8
		s.setHdrOffset(32, rl-4, rq, off)
		off += 4
	}

	i := 0
	io := off
	for i < len(value) {
		//		log.Println("len(rq)=", len(rq), "i=", i, "io=", io, "value[i]=", value[i])
		s.setInt(int(value[i]), rq, io)
		i++
		io += 4
	}

	rp := s.request(cmdSetSexp, rq, 0, len(rq))
	if rp != nil && rp.IsOk() {
		return
	}
	err = errors.New("Assign failed")
	return
}

func (s *session) AssignStrArray(symbol string, value []string) (err error) {
	rl := 0
	i := 0
	for i < len(value) {
		b := []byte(value[i])
		if len(b) > 0 {
			rl += len(b)
		}
		rl++
		i++
	}
	if (rl & 3) > 0 {
		rl = rl - (rl & 3) + 4
	}
	if rl > 0xfffff0 {
		rl += 4
	}
	rl += 4

	symn := []byte(symbol)
	sl := len(symn) + 1
	if (sl & 3) > 0 {
		sl = (sl & 0xfffffc) + 4
	}

	//	log.Println("rl=", rl, "sl=", sl)

	var rq []byte

	if rl > 0xfffff0 {
		rq = make([]byte, sl+rl+12)
	} else {
		rq = make([]byte, sl+rl+8)
	}

	ic := 0
	for ; ic < len(symn); ic++ {
		rq[ic+4] = symn[ic]
	}
	for ic < sl {
		rq[ic+4] = 0
		ic++
	}

	s.setHdrOffset(dtString, sl, rq, 0)
	s.setHdrOffset(dtSexp, rl, rq, sl+4)

	var off int
	if rl > 0xfffff0 {
		off = sl + 12
		s.setHdrOffset(34, rl-8, rq, off)
		off += 8
	} else {
		off = sl + 8
		s.setHdrOffset(34, rl-4, rq, off)
		off += 4
	}

	i = 0
	io := off
	for i < len(value) {
		b := []byte(value[i])
		if len(b) > 0 {
			copy(rq[io:io+len(b)], b[:])
			io += len(b)
		}
		rq[io] = 0
		io++
		i++
	}
	i = io - off
	for (i & 3) != 0 {
		rq[io] = 1
		io++
		i++
	}

	rp := s.request(cmdSetSexp, rq, 0, len(rq))
	if rp != nil && rp.IsOk() {
		return
	}
	err = errors.New("Assign failed")
	return

}

func (s *session) AssignByteArray(symbol string, value []byte) (err error) {
	rl := len(value) + 4
	if (rl & 3) > 0 {
		rl = rl - (rl & 3) + 4
	}
	if rl > 0xfffff0 {
		rl += 4
	}
	rl += 4

	symn := []byte(symbol)
	sl := len(symn) + 1
	if (sl & 3) > 0 {
		sl = (sl & 0xfffffc) + 4
	}

	//	log.Println("rl=", rl, "sl=", sl)

	var rq []byte

	if rl > 0xfffff0 {
		rq = make([]byte, sl+rl+12)
	} else {
		rq = make([]byte, sl+rl+8)
	}

	ic := 0
	for ; ic < len(symn); ic++ {
		rq[ic+4] = symn[ic]
	}
	for ic < sl {
		rq[ic+4] = 0
		ic++
	}

	s.setHdrOffset(dtString, sl, rq, 0)
	s.setHdrOffset(dtSexp, rl, rq, sl+4)

	var off int
	if rl > 0xfffff0 {
		off = sl + 12
		s.setHdrOffset(37, rl-8, rq, off)
		off += 8
	} else {
		off = sl + 8
		s.setHdrOffset(37, rl-4, rq, off)
		off += 4
	}

	s.setInt(len(value), rq, off)
	off += 4
	copy(rq[off:off+len(value)], value)

	rp := s.request(cmdSetSexp, rq, 0, len(rq))
	if rp != nil && rp.IsOk() {
		return
	}
	err = errors.New("Assign failed")
	return
}

func (s *session) AssignStr(symbol string, value string) (err error) {
	symn := []byte(symbol)
	ctn := []byte(value)

	sl := len(symn) + 1
	cl := len(ctn) + 1

	if (sl & 3) > 0 {
		sl = (sl & 0xfffffc) + 4
	}
	if (cl & 3) > 0 {
		cl = (cl & 0xfffffc) + 4
	}

	rq := make([]byte, sl+4+cl+4)

	ic := 0
	for ; ic < len(symn); ic++ {
		rq[ic+4] = symn[ic]
	}
	for ic < sl {
		rq[ic+4] = 0
		ic++
	}
	for ic = 0; ic < len(ctn); ic++ {
		rq[ic+sl+8] = ctn[ic]
	}
	for ic < cl {
		rq[ic+sl+8] = 0
		ic++
	}

	s.setHdrOffset(dtString, sl, rq, 0)
	s.setHdrOffset(dtString, cl, rq, sl+4)

	rp := s.request(cmdSetSexp, rq, 0, len(rq))
	if rp != nil && rp.IsOk() {
		return
	}
	err = errors.New("Assign failed")
	return
}
