# Build Image
```
docker build -t ifs_4205_sql .
```

# Run Container
```
docker run \
--name ifs_4205_mysql_db \
-d \
-p 3306:3306 \
-v mysql_data:/var/lib/mysql \
ifs_4205_sql:latest \
--temptable-max-ram=268435456 \
--slave-max-allowed-packet=268435456 \
--max-binlog-size=268435456
```

# Get Bash in Container
```
docker exec -it ifs_4205_sql bash
```
