#!/bin/bash
docker run -dit --name trd -p 8081:80 cylabs/cy-threat-response
docker exec -it trd bash
