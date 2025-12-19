sudo apt-get update

# make
sudo apt-get install -y make

# golang
sudo apt-get install -y golang-1.23 golang-1.23-go golang-1.23-src

sudo ln -sf /usr/lib/go-1.23/bin/go /usr/local/bin/go
sudo ln -sf /usr/lib/go-1.23/bin/gofmt /usr/local/bin/gofmt

# compiler
sudo apt-get install -y llvm clang lld libelf-dev zlib1g-dev pkg-config gcc g++ libc6-dev-i386


# headers
sudo apt-get install -y build-essential libc6-dev linux-libc-dev

# bpf
sudo apt-get install -y libbpf-dev libelf-dev zlib1g-dev pkg-config

# go env
export GOPROXY=https://artifactory.rbx.com/api/go/go-all
export GONOSUMDB=github.rbx.com
go env -json GOPROXY GONOSUMDB GOPRIVATE GONOPROXY





