go get
GOOS=linux CGO_ENABLED=0 go build main.go
zip rotate-key.zip main
rm main