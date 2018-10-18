# IFS4205

### Quick Setup

1. Create a virtualenv 
```
# initilise
> virtualenv python3 -p python3

# activate
> source python3/bin/activate

# install packages
> pip3 install -r requirements.txt
```

2. Initialise databse. Make sure you have mysql installed and update connection settings in `subsystem2/subsystem2/settings.py`.
```
> cd webapp
> ./manage.py migrate
```

3. Run
> ./manage.py runserver