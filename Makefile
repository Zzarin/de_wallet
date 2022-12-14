run_client:
	docker run -it -p 30303:30303 ethereum/client-go

run_client2:
	docker run -d --name ethereum-node -v /zar/ethereum:/root -p 8545:8545 -p 30303:30303 ethereum/client-go
