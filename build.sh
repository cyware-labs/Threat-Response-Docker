#!/bin/bash
docker run -dit --name trd -p 8081:80 cyware/threatresponsedocker
docker exec -it trd bash
