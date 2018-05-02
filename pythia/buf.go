package pythia

// #include "virgil_pythia_c.h"
import "C"

// Buf is needed to pass memory from Go to C and back
type Buf struct {
	inBuf *C.pythia_buf_t
	data  []byte
}

// NewBuf allocates memory block of predefined size
func NewBuf(size int) *Buf {

	p := make([]byte, size)
	buf := C.pythia_buf_new()
	C.pythia_buf_setup(buf, (*C.uint8_t)(&p[0]), C.size_t(size), C.size_t(0))
	return &Buf{
		inBuf: buf,
		data:  p,
	}
}

// NewBufWithData allocates new buffer and sets it memory to data
func NewBufWithData(data []byte) *Buf {

	buf := C.pythia_buf_new()
	C.pythia_buf_setup(buf, (*C.uint8_t)(&data[0]), C.size_t(len(data)), C.size_t(len(data)))
	return &Buf{
		inBuf: buf,
		data:  data,
	}
}

// GetData returns as many bytes as were written to buf by C code
func (b *Buf) GetData() []byte {
	newSize := int(b.inBuf.len)
	if newSize > len(b.data) {
		newSize = len(b.data)
	}
	return b.data[:newSize]
}

// Close frees memory allocated by Buf in C code
func (b *Buf) Close() {
	C.pythia_buf_free(b.inBuf)
}
