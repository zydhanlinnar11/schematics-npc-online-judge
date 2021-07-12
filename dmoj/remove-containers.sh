#!/bin/bash

docker container rm dmoj_nginx
docker container rm dmoj_bridged_1
docker container rm dmoj_celery_1
docker container rm dmoj_site_1
docker container rm dmoj_base_1
docker container rm dmoj_redis
docker container rm dmoj_mysql
