# Use an official MySQL runtime as a parent image
FROM mysql:latest

# Copy startup scripts
# ADD ./sql_scripts /docker-entrypoint-initdb.d

# Make port 3306 available to the world outside this container
EXPOSE 3306

# Define environment variable
ENV MYSQL_RANDOM_ROOT_PASSWORD=yes
ENV MYSQL_DATABASE=ifs4205
ENV MYSQL_ALLOW_EMPTY_PASSWORD=no