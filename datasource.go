package virgil_crypto_go

import (
	"io"
)

type dataSource struct {
	reader io.Reader
	hasData bool
	buf []byte

}

func NewDataSource(reader io.Reader) *dataSource{
	return &dataSource{
		hasData:true,
		buf: make([]byte, 4096),
		reader:reader,
	}
}

func (d *dataSource) HasData() (_swig_ret bool) {
	return d.hasData
}

func (d *dataSource) Read() (_swig_ret VirgilByteArray) {
	if(! d.hasData){
		return
	}
	read, err := d.reader.Read(d.buf)
	if(read < len(d.buf) || err != nil){
		d.hasData = false
	}
	return ToVirgilByteArray(d.buf[:read])
}

