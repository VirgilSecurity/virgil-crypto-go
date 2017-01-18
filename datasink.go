package virgil_crypto_go

import (
	"io"
)

type dataSink struct{
	writer io.Writer
	isGood bool
}

func NewDataSink(writer io.Writer) *dataSink {
	return &dataSink{
		isGood:true,
		writer:writer,
	}
}

func (d *dataSink) IsGood() (_swig_ret bool) {
	return d.isGood
}

func (d *dataSink) Write(b VirgilByteArray) {
	if(! d.isGood){
		return
	}
	buf := ToSlice(b)
	_, err := d.writer.Write(buf)
	if err != nil{
		d.isGood = false
	}
}
