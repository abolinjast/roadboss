Requirements
go
ubuntu/debian

run
```bash
sudo apt install clang llvm libbpf-dev
```

and then
```bash
go generate ./cmd/roadboss
go build -o roadboss ./cmd/roadboss
```

