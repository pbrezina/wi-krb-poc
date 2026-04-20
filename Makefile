up:
	docker-compose up

down:
	docker-compose down -v
	rm -f certs/tmp/*

stop:
	docker-compose stop

update-ca-bundle:
	./setup/update-ca-bundle.sh

first-time-up:
	docker compose up -d --wait --build spire-server ipa staging
	./setup/spire-import-entries.sh
	./setup/ipa-setup.sh
	./setup/ipa-setup-keytab.sh
	docker compose up -d --wait spire-agent
	docker-compose up
