package roger

type command int

const (
	cmdLogin   command = 1
	cmdEval    command = 3
	cmdSetSexp command = 32
)
