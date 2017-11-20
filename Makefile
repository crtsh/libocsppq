export GOPATH=/home/rob/go

libocsppq.so:
	$(GOPATH)/bin/plgo .

clean:
	rm -rf build
