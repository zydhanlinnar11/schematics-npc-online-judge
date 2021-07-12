#!/bin/bash

cd ../
git submodule update --init --recursive
cd dmoj
./scripts/initialize

docker-compose up -d site

./scripts/migrate
./scripts/copy_static
./scripts/manage.py loaddata navbar
./scripts/manage.py loaddata language_small
./scripts/manage.py loaddata demo
