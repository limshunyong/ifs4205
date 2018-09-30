### Run Minio Server
```
./ifsminio server \minio
```
Resource: https://docs.minio.io/docs/minio-quickstart-guide.html

### Run Minio Client
```
./mc COMMAND TARGET
```

#### List Bucket and Objects
```
./mc ls ifsminio
```
#### Find an Object
```
./mc find ifsminio/BUCKETNAME OBJECTNAME
```
More: https://docs.minio.io/docs/minio-client-complete-guide
