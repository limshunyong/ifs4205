# Build Image
```
docker build -t ifs_4205_sql .
```

# Run Container
```
docker run \
-d \
-p 3306:3306 \
--name ifs_4205_sql_1 \
-v mysql_data:/var/lib/mysql \
ifs_4205_sql
```

# Get Bash in Container
```
docker exec -it ifs_4205_sql bash
```