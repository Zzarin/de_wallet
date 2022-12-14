package localFile

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"io"
	"os"
)

type FileLocal struct {
	name string
}

func NewLocalFile(name string) *FileLocal {
	return &FileLocal{
		name: name,
	}
}

func (l *FileLocal) Read(ctx context.Context, newLine chan []byte, done chan bool) (err error) {
	file, err := os.Open(l.name)
	if err != nil {
		return fmt.Errorf("open file %w", err)
	}
	defer file.Close()
	var offset int64
	buf := make([]byte, 60)
	for {
		_, err := file.ReadAt(buf, offset)
		offset += int64(len(buf))

		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
			}
			break
		}
		newLine <- buf
	}

	done <- true
	close(done)
	close(newLine)
	return nil
}

func (l *FileLocal) Write(ctx context.Context, data []byte) error {
	file, err := os.OpenFile(l.name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open/create file for writing %w", err)
	}
	defer func(f func() error) {
		errClose := f()
		if err == nil {
			err = errClose
		} else if errClose != nil {
			log.Error("file closing", errClose)
		}
	}(file.Close)

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("write to file %w", err)
	}
	return nil
}
