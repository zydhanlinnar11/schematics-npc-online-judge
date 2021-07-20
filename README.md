DMOJ Docker [![Build Status](https://github.com/zydhanlinnar11/schematics-npc-online-judge/workflows/Build%20Docker%20Images/badge.svg)](https://github.com/zydhanlinnar11/schematics-npc-online-judge/actions/)
=====

This repository contains the Docker files to run a clone of the [DMOJ site](https://github.com/DMOJ/online-judge). It does not configure any additional services, such as camo, mathoid, and texoid.

## Installation

First, [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) must be installed. Installation instructions can be found on their respective websites.

Clone the repository:
```sh
git clone https://github.com/zydhanlinnar11/dmoj-docker
cd dmoj-docker
git submodule update --init --recursive
cd dmoj
```
From now on, it is assumed you are in the `dmoj` directory.

Initialize the setup by moving the configuration files into the submodule and by creating the necessary directories:
```sh
./scripts/initialize
```

Configure the environment variables in the files in `dmoj/environment/`. In particular, set the MYSQL passwords in `mysql.env` and `mysql-admin.env`, and the host and secret key in `site.env`. Also, configure the `server_name` directive in `dmoj/nginx/conf.d/nginx.conf`.

Next, build the images:
```sh
docker-compose build
```

Start up the site, so you can perform the initial migrations and generate the static files:
```sh
docker-compose up -d site
```

You will need to generate the schema for the database, since it is currently empty:
```sh
./scripts/migrate
```

You will also need to generate the static files:
```
./scripts/copy_static
```

Finally, the DMOJ comes with fixtures so that the initial install is not blank. They can be loaded with the following commands:
```sh
./scripts/manage.py loaddata navbar
./scripts/manage.py loaddata language_all
./scripts/manage.py loaddata panitia
./scripts/manage.py loaddata role
./scripts/manage.py loaddata problemgroup
./scripts/manage.py loaddata problemtag
./scripts/manage.py loaddata blogpost
./scripts/manage.py loaddata contest
./scripts/manage.py loaddata pesertadummy
```

## Usage
```
docker-compose up -d
```

## Notes

### Migrating
As the DMOJ site is a Django app, you may need to migrate whenever you update. Assuming the site container is running, running the following command should suffice:
```sh
./scripts/migrate
```

### Managing Static Files
If your static files ever change, you will need to rebuild them:
```
./scripts/copy_static
```

### Updating The Site
Updating various sections of the site requires different images to be rebuilt.

If any prerequisites were modified, you will need to rebuild most of the images:
```sh
docker-compose up -d --build base site celery bridged
```
If the static files are modified, read the section on [Managing Static Files](#managing-static-files).

If only the source code is modified, a restart is sufficient:
```sh
docker-compose restart site celery bridged
```

### Deployment to Schematics Website

The `docker-compose.yml` configures Nginx to publish to port 80. This site published from [https://sch-npc-junior.zydhan.xyz/sch-npc/portal/junior](https://sch-npc-junior.zydhan.xyz/sch-npc/portal/junior)

Example Nginx configuration file on your host machine would be:
```
server {
    listen 443;
    listen [::]:443;

    add_header X-UA-Compatible "IE=Edge,chrome=1";
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location /sch-npc/portal/junior {
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_set_header Host $http_host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_pass https://sch-npc-junior.zydhan.xyz/sch-npc/portal/junior/;
    }
}
```

### About subdirectories and domain

We need to change nginx.conf, demo and navbar fixtures, uwsgi.ini, trusted origins in settings.py, static_url and media_url in local_settings.py.
